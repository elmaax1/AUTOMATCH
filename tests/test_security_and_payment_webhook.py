import hashlib
import hmac
import os
from copy import deepcopy
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import dotenv

with patch.object(dotenv, "load_dotenv"), patch.dict(
    os.environ,
    {
        "AUTOMATCH_ENV": "test",
        "AUTOMATCH_SECRET_KEY": "test-only-session-key",
    },
):
    import app as automatch


class FakeResult:
    def __init__(self, row=None, rowcount=1, rows=None):
        self.row = row
        self.rowcount = rowcount
        self.rows = rows

    def fetchone(self):
        return self.row

    def fetchall(self):
        if self.rows is not None:
            return self.rows
        return [self.row] if self.row is not None else []


class FakeDatabase:
    """Test double for the migrated payments schema; it does not validate DDL."""

    def __init__(
        self,
        payment=None,
        payments=None,
        vehicle=None,
        payment_update_rowcount=1,
        payment_columns=None,
    ):
        self.payment_columns = set(
            {
                "beneficiary_user_id",
                "initiated_by_admin",
            }
            if payment_columns is None
            else payment_columns
        )
        self.payments = payments or ([payment] if payment else [])
        self.payment = payment or (self.payments[0] if self.payments else None)
        self.vehicle = vehicle or {
            "id": self.payment["vehicle_id"] if self.payment else 34,
            "user_id": self.payment.get("beneficiary_user_id", 9)
            if self.payment else 9,
            "status": "published",
        }
        self.vehicle.setdefault("featured", False)
        self.vehicle.setdefault("featured_until", None)
        self.featured_until = self.vehicle["featured_until"]
        self.payment_select = ""
        self.payment_update_params = None
        self.vehicle_updates = 0
        self.payment_insert_params = None
        self.payment_update_rowcount = payment_update_rowcount
        self.executed_queries = []
        self._snapshot = None

    def __enter__(self):
        self._snapshot = {
            "payments": [(row, deepcopy(row)) for row in self.payments],
            "vehicle": deepcopy(self.vehicle),
            "featured_until": self.featured_until,
        }
        return self

    def __exit__(self, exception_type, exception, traceback):
        if exception_type is not None and self._snapshot is not None:
            for row, values in self._snapshot["payments"]:
                row.clear()
                row.update(values)
            self.vehicle.clear()
            self.vehicle.update(self._snapshot["vehicle"])
            self.featured_until = self._snapshot["featured_until"]
        return False

    def execute(self, query, params=()):
        normalized_query = " ".join(query.split())
        self.executed_queries.append((normalized_query, params))

        if normalized_query.startswith("SELECT * FROM vehicles"):
            return FakeResult(self.vehicle)

        if normalized_query.startswith("INSERT INTO payments"):
            required_columns = {
                "beneficiary_user_id",
                "initiated_by_admin",
            }
            missing_columns = required_columns - self.payment_columns
            if missing_columns:
                raise RuntimeError(
                    "La migración de pagos es requisito; faltan columnas: "
                    + ", ".join(sorted(missing_columns))
                )
            self.payment_insert_params = params
            payment = {
                "id": len(self.payments) + 1,
                "user_id": params[0],
                "vehicle_id": params[1],
                "beneficiary_user_id": params[2],
                "initiated_by_admin": params[3],
                "plan_days": params[4],
                "amount": Decimal(str(params[5])),
                "currency": "ARS",
                "status": "pending",
                "external_reference": params[6],
                "idempotency_key": params[7],
                "mp_order_id": None,
                "checkout_url": None,
            }
            self.payments.append(payment)
            self.payment = payment
            return FakeResult()

        if normalized_query.startswith("SELECT id, vehicle_id, plan_days"):
            self.payment_select = normalized_query
            reference, order_id = params
            matches = [
                payment for payment in self.payments
                if payment["external_reference"] == reference
                and (
                    payment["mp_order_id"] is None
                    or payment["mp_order_id"] == order_id
                )
            ]
            return FakeResult(rows=matches)

        if normalized_query.startswith("SELECT id FROM vehicles"):
            vehicle_id = params[0]
            if (
                self.vehicle["id"] == vehicle_id
                and self.vehicle["status"] == "published"
            ):
                return FakeResult({"id": vehicle_id})
            return FakeResult()

        if normalized_query.startswith("UPDATE vehicles"):
            self.vehicle_updates += 1
            self.featured_until = datetime(
                2026, 12, 1, tzinfo=timezone.utc
            )
            self.vehicle["featured"] = True
            self.vehicle["featured_until"] = self.featured_until
            return FakeResult({
                "featured": self.vehicle["featured"],
                "featured_until": self.featured_until,
            })

        if normalized_query.startswith("UPDATE payments"):
            self.payment_update_params = params
            if "SET status = 'error'" in normalized_query:
                for payment in self.payments:
                    if payment["external_reference"] == params[0]:
                        payment["status"] = "error"
                return FakeResult(rowcount=1)

            if "checkout_url = COALESCE" in normalized_query:
                order_id, checkout_url, reference, expected_id = params
                matches = [
                    payment for payment in self.payments
                    if payment["external_reference"] == reference
                    and (
                        payment["mp_order_id"] is None
                        or payment["mp_order_id"] == expected_id
                    )
                ]
                for payment in matches:
                    payment["mp_order_id"] = (
                        payment["mp_order_id"] or order_id
                    )
                    payment["checkout_url"] = (
                        checkout_url or payment["checkout_url"]
                    )
                return FakeResult(rowcount=len(matches))

            if self.payment_update_rowcount == 1 and self.payment:
                order_id = params[0]
                self.payment["mp_order_id"] = (
                    self.payment["mp_order_id"] or order_id
                )
                self.payment["status"] = "approved"
                self.payment["expires_at"] = params[1]
                self.payment["approved_at"] = datetime(
                    2026, 11, 25, tzinfo=timezone.utc
                )
            return FakeResult(rowcount=self.payment_update_rowcount)

        raise AssertionError("Consulta de base no simulada en la prueba.")


class SecurityAndPaymentWebhookTests(unittest.TestCase):
    def test_production_requires_configured_secret_without_creating_file(self):
        with TemporaryDirectory() as directory:
            secret_file = Path(directory) / "secret"

            with self.assertRaisesRegex(RuntimeError, "AUTOMATCH_SECRET_KEY"):
                automatch.get_app_secret_key(secret_file, None, "production")

            self.assertFalse(secret_file.exists())

    def test_local_secret_fallback_is_stable_and_cookie_flags_are_secure(self):
        with TemporaryDirectory() as directory:
            secret_file = Path(directory) / "secret"
            first_key = automatch.get_app_secret_key(secret_file, None, "test")
            second_key = automatch.get_app_secret_key(secret_file, None, "test")

        self.assertEqual(first_key, second_key)
        self.assertTrue(automatch.secure_session_cookie("production", "0"))
        self.assertTrue(automatch.secure_session_cookie("test", "1"))
        self.assertFalse(automatch.secure_session_cookie("test", "0"))
        self.assertTrue(automatch.app.config["SESSION_COOKIE_HTTPONLY"])
        self.assertEqual(automatch.app.config["SESSION_COOKIE_SAMESITE"], "Lax")

    def test_mla_order_with_exact_accredited_amount_activates_payment(self):
        order_id = "test-order-123"
        request_id = "test-request-123"
        reference = "automatch-test-reference"
        secret = "test-only-webhook-secret"
        payment = {
            "id": 12,
            "vehicle_id": 34,
            "plan_days": 7,
            "amount": Decimal("2000"),
            "currency": "ARS",
            "status": "pending",
            "external_reference": reference,
            "mp_order_id": None,
        }
        database = FakeDatabase(payment)
        order = self._approved_order(order_id, reference)
        signature = self._signature(order_id, request_id, secret)

        with patch.object(automatch, "is_production", True):
            with patch.dict(os.environ, {
                "MERCADOPAGO_WEBHOOK_SECRET": secret,
                "MERCADOPAGO_ACCESS_TOKEN": "test-only-access-token",
            }):
                with patch.object(automatch, "get_db", return_value=database):
                    with patch.object(
                        automatch.requests,
                        "get",
                        return_value=SimpleNamespace(ok=True, json=lambda: order),
                    ):
                        response = automatch.app.test_client().post(
                            "/webhook/mercadopago?data.id={}".format(order_id),
                            json={
                                "type": "order",
                                "live_mode": True,
                                "data": {"id": order_id},
                            },
                            headers={
                                "x-signature": signature,
                                "x-request-id": request_id,
                            },
                        )

        self.assertEqual(response.status_code, 200)
        self.assertIn("mp_order_id IS NULL", database.payment_select)
        self.assertEqual(database.payment_update_params[0], order_id)
        self.assertEqual(payment["mp_order_id"], order_id)
        self.assertEqual(payment["status"], "approved")
        self.assertEqual(database.vehicle_updates, 1)

    def test_two_accredited_transactions_sum_to_plan_amount(self):
        payment = self._pending_payment("automatch-two-transactions")
        database = FakeDatabase(payment)
        order = self._approved_order(
            "two-transactions-order",
            payment["external_reference"],
        )
        order["transactions"]["payments"] = [
            {
                "amount": "1000.00",
                "paid_amount": "1000.00",
                "status": "processed",
                "status_detail": "accredited",
            },
            {
                "amount": "1000.00",
                "paid_amount": "1000.00",
                "status": "processed",
                "status_detail": "accredited",
            },
        ]

        response = self._send_webhook(database, order)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(database.vehicle_updates, 1)
        self.assertEqual(payment["status"], "approved")

    def test_duplicate_webhook_does_not_activate_vehicle_twice(self):
        payment = {
            "id": 12,
            "vehicle_id": 34,
            "plan_days": 7,
            "amount": Decimal("2000"),
            "currency": "ARS",
            "status": "pending",
            "external_reference": "automatch-test-reference",
            "mp_order_id": None,
        }
        database = FakeDatabase(payment)
        order_id = "test-order-123"
        request_id = "test-request-123"
        secret = "test-only-webhook-secret"
        order = self._approved_order(
            order_id,
            payment["external_reference"],
        )
        client = automatch.app.test_client()

        with patch.dict(os.environ, {
            "MERCADOPAGO_WEBHOOK_SECRET": secret,
            "MERCADOPAGO_ACCESS_TOKEN": "test-only-access-token",
        }):
            with patch.object(automatch, "get_db", return_value=database):
                with patch.object(
                    automatch.requests,
                    "get",
                    return_value=SimpleNamespace(ok=True, json=lambda: order),
                ):
                    for _ in range(2):
                        response = client.post(
                            "/webhook/mercadopago?data.id={}".format(order_id),
                            json={
                                "type": "order",
                                "live_mode": False,
                                "data": {"id": order_id},
                            },
                            headers={
                                "x-signature": self._signature(
                                    order_id, request_id, secret
                                ),
                                "x-request-id": request_id,
                            },
                        )

        vencimiento_primera_aplicacion = database.featured_until
        self.assertEqual(response.status_code, 200)
        self.assertEqual(database.vehicle_updates, 1)
        self.assertEqual(payment["status"], "approved")
        self.assertEqual(
            database.featured_until,
            vencimiento_primera_aplicacion,
        )

    def test_duplicate_external_reference_fails_closed(self):
        order_id = "test-order-duplicate-ref"
        reference = "automatch-duplicated-reference"
        payments = [
            {
                "id": payment_id,
                "vehicle_id": 34 + payment_id,
                "plan_days": 7,
                "amount": Decimal("2000"),
                "currency": "ARS",
                "status": "pending",
                "external_reference": reference,
                "mp_order_id": None,
            }
            for payment_id in (1, 2)
        ]
        database = FakeDatabase(payments=payments)
        order = self._approved_order(order_id, reference)

        response = self._send_webhook(database, order)

        self.assertEqual(response.status_code, 503)
        self.assertEqual(database.vehicle_updates, 0)
        self.assertTrue(all(p["status"] == "pending" for p in payments))

    def test_incorrect_order_amount_does_not_activate_vehicle(self):
        payment = self._pending_payment("automatch-wrong-amount")
        database = FakeDatabase(payment)
        order = self._approved_order(
            "wrong-amount-order",
            payment["external_reference"],
        )
        order["total_amount"] = "1999.99"

        response = self._send_webhook(database, order)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(database.vehicle_updates, 0)
        self.assertEqual(payment["status"], "pending")

    def test_partial_transaction_does_not_activate_vehicle(self):
        payment = self._pending_payment("automatch-partial-transaction")
        database = FakeDatabase(payment)
        order = self._approved_order(
            "partial-transaction-order",
            payment["external_reference"],
        )
        order["total_paid_amount"] = "1000.00"
        order["transactions"]["payments"][0]["paid_amount"] = "1000.00"

        response = self._send_webhook(database, order)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(database.vehicle_updates, 0)
        self.assertEqual(payment["status"], "pending")

    def test_overpaid_transaction_does_not_activate_vehicle(self):
        payment = self._pending_payment("automatch-overpaid-transaction")
        database = FakeDatabase(payment)
        order = self._approved_order(
            "overpaid-transaction-order",
            payment["external_reference"],
        )
        order["total_paid_amount"] = "2000.01"
        order["transactions"]["payments"][0]["amount"] = "2000.01"
        order["transactions"]["payments"][0]["paid_amount"] = "2000.01"

        response = self._send_webhook(database, order)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(database.vehicle_updates, 0)
        self.assertEqual(payment["status"], "pending")

    def test_non_mla_site_does_not_activate_vehicle(self):
        payment = self._pending_payment("automatch-non-mla")
        database = FakeDatabase(payment)
        order = self._approved_order(
            "non-mla-order",
            payment["external_reference"],
        )
        order["country_code"] = "MLB"

        response = self._send_webhook(database, order)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(database.executed_queries, [])
        self.assertEqual(database.vehicle_updates, 0)
        self.assertEqual(payment["status"], "pending")

    def test_missing_country_code_does_not_activate_vehicle(self):
        payment = self._pending_payment("automatch-missing-country")
        database = FakeDatabase(payment)
        order = self._approved_order(
            "missing-country-order",
            payment["external_reference"],
        )
        del order["country_code"]

        response = self._send_webhook(database, order)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(database.executed_queries, [])
        self.assertEqual(database.vehicle_updates, 0)
        self.assertEqual(payment["status"], "pending")

    def test_waiting_capture_transaction_does_not_activate_vehicle(self):
        payment = self._pending_payment("automatch-waiting-capture")
        database = FakeDatabase(payment)
        order = self._approved_order(
            "waiting-capture-order",
            payment["external_reference"],
        )
        order["status"] = "action_required"
        order["status_detail"] = "waiting_capture"
        order["transactions"]["payments"][0]["status"] = "action_required"
        order["transactions"]["payments"][0]["status_detail"] = (
            "waiting_capture"
        )
        order["transactions"]["payments"][0]["paid_amount"] = "0.00"

        response = self._send_webhook(database, order)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(database.vehicle_updates, 0)
        self.assertEqual(payment["status"], "pending")

    def test_processed_order_without_accreditation_does_not_activate_vehicle(self):
        payment = self._pending_payment("automatch-not-accredited")
        database = FakeDatabase(payment)
        order = self._approved_order(
            "not-accredited-order",
            payment["external_reference"],
        )
        order["status_detail"] = "in_process"
        order["transactions"]["payments"][0]["status_detail"] = "in_process"

        response = self._send_webhook(database, order)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(database.vehicle_updates, 0)
        self.assertEqual(payment["status"], "pending")

    def test_order_id_mismatch_does_not_reach_payment_lookup(self):
        reference = "automatch-order-id-mismatch"
        database = FakeDatabase(payment={
            "id": 12,
            "vehicle_id": 34,
            "plan_days": 7,
            "amount": Decimal("2000"),
            "currency": "ARS",
            "status": "pending",
            "external_reference": reference,
            "mp_order_id": None,
        })
        order = self._approved_order("another-order-id", reference)

        response = self._send_webhook(
            database,
            order,
            notified_order_id="notified-order-id",
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(database.executed_queries, [])
        self.assertEqual(database.vehicle_updates, 0)

    def test_external_reference_mismatch_does_not_activate_vehicle(self):
        payment = self._pending_payment("automatch-original-reference")
        database = FakeDatabase(payment)
        order = self._approved_order(
            "reference-mismatch-order",
            "automatch-different-reference",
        )

        response = self._send_webhook(database, order)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(database.vehicle_updates, 0)
        self.assertEqual(payment["status"], "pending")

    def test_payment_update_failure_rolls_back_vehicle_feature(self):
        payment = self._pending_payment("automatch-rollback")
        previous_featured_until = datetime(
            2026, 11, 30, tzinfo=timezone.utc
        )
        database = FakeDatabase(
            payment,
            vehicle={
                "id": 34,
                "user_id": 9,
                "status": "published",
                "featured": True,
                "featured_until": previous_featured_until,
            },
            payment_update_rowcount=0,
        )
        payment_before = deepcopy(payment)
        vehicle_before = deepcopy(database.vehicle)
        featured_until_before = database.featured_until
        order = self._approved_order(
            "rollback-order-id",
            payment["external_reference"],
        )

        response = self._send_webhook(database, order)

        self.assertEqual(response.status_code, 503)
        self.assertEqual(payment, payment_before)
        self.assertEqual(database.vehicle, vehicle_before)
        self.assertEqual(database.featured_until, featured_until_before)

    def test_owner_and_admin_are_recorded_separately_from_beneficiary(self):
        vehicle = {"id": 34, "user_id": 7, "status": "published"}
        cases = [
            ({"id": 7, "email": "owner@example.test", "role": "user"}, False),
            ({"id": 99, "email": "admin@example.test", "role": "admin"}, True),
        ]

        for payer, is_admin in cases:
            response, database, _ = self._create_payment(
                payer,
                vehicle,
                [self._successful_order_response()],
            )

            self.assertEqual(response.status_code, 302)
            self.assertEqual(database.payment_insert_params[0], payer["id"])
            self.assertEqual(database.payment_insert_params[1], vehicle["id"])
            self.assertEqual(database.payment_insert_params[2], vehicle["user_id"])
            self.assertEqual(database.payment_insert_params[3], is_admin)
            self.assertEqual(database.payment["user_id"], payer["id"])
            self.assertEqual(
                database.payment["beneficiary_user_id"],
                vehicle["user_id"],
            )
            self.assertEqual(
                database.payment["initiated_by_admin"],
                is_admin,
            )

    def test_non_admin_cannot_pay_for_another_users_vehicle(self):
        payer = {"id": 8, "email": "other@example.test", "role": "user"}
        vehicle = {"id": 34, "user_id": 7, "status": "published"}
        response, database, request_mock = self._create_payment(
            payer,
            vehicle,
            [self._successful_order_response()],
        )

        self.assertEqual(response.status_code, 403)
        self.assertIsNone(database.payment_insert_params)
        request_mock.assert_not_called()

    def test_order_uses_manual_processing_and_automatic_capture(self):
        payer = {"id": 7, "email": "owner@example.test", "role": "user"}
        vehicle = {"id": 34, "user_id": 7, "status": "published"}
        response, _, request_mock = self._create_payment(
            payer,
            vehicle,
            [self._successful_order_response()],
        )

        self.assertEqual(response.status_code, 302)
        order_payload = request_mock.call_args.kwargs["json"]
        self.assertEqual(order_payload["processing_mode"], "manual")
        self.assertEqual(order_payload["capture_mode"], "automatic")

    def test_payment_insert_requires_migration_columns(self):
        database = FakeDatabase(payment_columns=set())

        with self.assertRaisesRegex(
            RuntimeError,
            "La migración de pagos es requisito",
        ):
            database.execute(
                "INSERT INTO payments "
                "(beneficiary_user_id, initiated_by_admin) VALUES (%s, %s)",
                (7, False),
            )

    def test_timeout_retry_reuses_idempotency_key_and_payload(self):
        payer = {"id": 7, "email": "owner@example.test", "role": "user"}
        vehicle = {"id": 34, "user_id": 7, "status": "published"}
        response, database, request_mock = self._create_payment(
            payer,
            vehicle,
            [
                automatch.requests.Timeout("response timed out"),
                self._successful_order_response(),
            ],
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(request_mock.call_count, 2)
        first_call, second_call = request_mock.call_args_list
        key = database.payment_insert_params[7]
        self.assertEqual(
            first_call.kwargs["headers"]["X-Idempotency-Key"],
            key,
        )
        self.assertEqual(
            second_call.kwargs["headers"]["X-Idempotency-Key"],
            key,
        )
        self.assertEqual(first_call.kwargs["json"], second_call.kwargs["json"])
        self.assertEqual(database.payment["status"], "pending")

    def test_repeated_timeout_keeps_new_payment_pending(self):
        payer = {"id": 7, "email": "owner@example.test", "role": "user"}
        vehicle = {"id": 34, "user_id": 7, "status": "published"}
        response, database, request_mock = self._create_payment(
            payer,
            vehicle,
            [
                automatch.requests.Timeout("first timeout"),
                automatch.requests.Timeout("second timeout"),
            ],
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(request_mock.call_count, 2)
        self.assertEqual(database.payment["status"], "pending")
        self.assertFalse(any(
            "SET status = 'error'" in query
            for query, _ in database.executed_queries
        ))

    def test_definitive_rejection_after_timeout_keeps_payment_pending(self):
        payer = {"id": 7, "email": "owner@example.test", "role": "user"}
        vehicle = {"id": 34, "user_id": 7, "status": "published"}
        response, database, request_mock = self._create_payment(
            payer,
            vehicle,
            [
                automatch.requests.Timeout("response timed out"),
                SimpleNamespace(ok=False, status_code=400),
            ],
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(request_mock.call_count, 2)
        self.assertEqual(database.payment["status"], "pending")
        self.assertFalse(any(
            "SET status = 'error'" in query
            for query, _ in database.executed_queries
        ))

    def test_temporary_mercado_pago_error_retries_same_key_and_payload(self):
        payer = {"id": 7, "email": "owner@example.test", "role": "user"}
        vehicle = {"id": 34, "user_id": 7, "status": "published"}
        response, database, request_mock = self._create_payment(
            payer,
            vehicle,
            [
                SimpleNamespace(ok=False, status_code=503),
                self._successful_order_response(),
            ],
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(request_mock.call_count, 2)
        first_call, second_call = request_mock.call_args_list
        key = database.payment_insert_params[7]
        self.assertEqual(
            first_call.kwargs["headers"]["X-Idempotency-Key"],
            key,
        )
        self.assertEqual(
            second_call.kwargs["headers"]["X-Idempotency-Key"],
            key,
        )
        self.assertEqual(first_call.kwargs["json"], second_call.kwargs["json"])
        self.assertEqual(database.payment["status"], "pending")

    def test_mercado_pago_rejection_marks_payment_as_error(self):
        payer = {"id": 7, "email": "owner@example.test", "role": "user"}
        vehicle = {"id": 34, "user_id": 7, "status": "published"}
        response, database, request_mock = self._create_payment(
            payer,
            vehicle,
            [SimpleNamespace(ok=False, status_code=400)],
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(request_mock.call_count, 1)
        self.assertEqual(database.payment["status"], "error")

    def test_invalid_webhook_order_json_returns_service_unavailable(self):
        payment = self._pending_payment("automatch-invalid-json")
        database = FakeDatabase(payment)
        invalid_json_response = SimpleNamespace(
            ok=True,
            json=lambda: (_ for _ in ()).throw(ValueError("invalid JSON")),
        )

        response = self._send_webhook(
            database,
            self._approved_order(
                "invalid-json-order",
                payment["external_reference"],
            ),
            lookup_response=invalid_json_response,
        )

        self.assertEqual(response.status_code, 503)
        self.assertEqual(database.executed_queries, [])
        self.assertEqual(database.vehicle_updates, 0)
        self.assertEqual(payment["status"], "pending")

    def test_temporary_webhook_lookup_error_returns_service_unavailable(self):
        payment = self._pending_payment("automatch-temporary-error")
        database = FakeDatabase(payment)

        response = self._send_webhook(
            database,
            self._approved_order(
                "temporary-error-order",
                payment["external_reference"],
            ),
            lookup_response=SimpleNamespace(ok=False, status_code=503),
        )

        self.assertEqual(response.status_code, 503)
        self.assertEqual(database.executed_queries, [])
        self.assertEqual(database.vehicle_updates, 0)
        self.assertEqual(payment["status"], "pending")

    def test_test_environment_ignores_live_webhooks(self):
        request_id = "test-request-123"
        order_id = "live-order-123"
        secret = "test-only-webhook-secret"

        with patch.dict(os.environ, {
            "MERCADOPAGO_WEBHOOK_SECRET": secret,
            "MERCADOPAGO_ACCESS_TOKEN": "test-only-access-token",
        }):
            with patch.object(automatch.requests, "get") as get_order:
                with patch.object(automatch, "get_db") as get_database:
                    response = automatch.app.test_client().post(
                        "/webhook/mercadopago?data.id={}".format(order_id),
                        json={
                            "type": "order",
                            "live_mode": True,
                            "data": {"id": order_id},
                        },
                        headers={
                            "x-signature": self._signature(
                                order_id, request_id, secret
                            ),
                            "x-request-id": request_id,
                        },
                    )

        self.assertEqual(response.status_code, 200)
        get_order.assert_not_called()
        get_database.assert_not_called()

    def test_malformed_webhook_data_is_rejected_without_external_calls(self):
        with patch.dict(os.environ, {
            "MERCADOPAGO_WEBHOOK_SECRET": "test-only-webhook-secret",
            "MERCADOPAGO_ACCESS_TOKEN": "test-only-access-token",
        }):
            with patch.object(automatch.requests, "get") as get_order:
                with patch.object(automatch, "get_db") as get_database:
                    response = automatch.app.test_client().post(
                        "/webhook/mercadopago?data.id=malformed-order",
                        json={"type": "order", "data": []},
                    )

        self.assertEqual(response.status_code, 400)
        get_order.assert_not_called()
        get_database.assert_not_called()

    @staticmethod
    def _signature(order_id, request_id, secret, timestamp="123"):
        manifest = (
            "id:{};request-id:{};ts:{};".format(
                order_id, request_id, timestamp
            )
        )
        digest = hmac.new(
            secret.encode("utf-8"),
            manifest.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        return "ts={},v1={}".format(timestamp, digest)

    @staticmethod
    def _pending_payment(reference):
        return {
            "id": 12,
            "vehicle_id": 34,
            "plan_days": 7,
            "amount": Decimal("2000"),
            "currency": "ARS",
            "status": "pending",
            "external_reference": reference,
            "mp_order_id": None,
            "approved_at": None,
            "expires_at": None,
        }

    @staticmethod
    def _successful_order_response():
        return SimpleNamespace(
            ok=True,
            status_code=201,
            json=lambda: {
                "id": "test-created-order",
                "checkout_url": "https://checkout.example.test/order",
            },
        )

    @staticmethod
    def _approved_order(order_id, reference):
        return {
            "id": order_id,
            "country_code": "MLA",
            "external_reference": reference,
            "status": "processed",
            "status_detail": "accredited",
            "total_amount": "2000.00",
            "total_paid_amount": "2000.00",
            "transactions": {
                "payments": [{
                    "amount": "2000.00",
                    "paid_amount": "2000.00",
                    "status": "processed",
                    "status_detail": "accredited",
                }],
            },
        }

    def _send_webhook(
        self,
        database,
        order,
        notified_order_id=None,
        lookup_response=None,
    ):
        order_id = str(notified_order_id or order["id"])
        request_id = "test-webhook-request"
        secret = "test-only-webhook-secret"
        response_from_mp = lookup_response or SimpleNamespace(
            ok=True,
            json=lambda: order,
        )

        with patch.dict(os.environ, {
            "MERCADOPAGO_WEBHOOK_SECRET": secret,
            "MERCADOPAGO_ACCESS_TOKEN": "test-only-access-token",
        }):
            with patch.object(automatch, "is_production", False):
                with patch.object(automatch, "get_db", return_value=database):
                    with patch.object(
                        automatch.requests,
                        "get",
                        return_value=response_from_mp,
                    ):
                        return automatch.app.test_client().post(
                            "/webhook/mercadopago?data.id={}".format(order_id),
                            json={
                                "type": "order",
                                "live_mode": False,
                                "data": {"id": order_id},
                            },
                            headers={
                                "x-signature": self._signature(
                                    order_id, request_id, secret
                                ),
                                "x-request-id": request_id,
                            },
                        )

    def _create_payment(self, payer, vehicle, mercado_pago_responses):
        database = FakeDatabase(vehicle=vehicle)
        with patch.dict(os.environ, {
            "MERCADOPAGO_ACCESS_TOKEN": "test-only-access-token",
        }):
            with patch.object(automatch, "current_user", return_value=payer):
                with patch.object(automatch, "get_db", return_value=database):
                    with patch.object(
                        automatch.requests,
                        "post",
                        side_effect=mercado_pago_responses,
                    ) as request_mock:
                        client = automatch.app.test_client()
                        with client.session_transaction() as flask_session:
                            flask_session["user_id"] = payer["id"]
                            flask_session["feature_csrf_token"] = (
                                "test-feature-csrf-token"
                            )
                        response = client.post(
                            "/vehiculo/{}/destacar".format(vehicle["id"]),
                            data={
                                "csrf_token": "test-feature-csrf-token",
                                "plan_days": "7",
                            },
                        )
        return response, database, request_mock


if __name__ == "__main__":
    unittest.main()
