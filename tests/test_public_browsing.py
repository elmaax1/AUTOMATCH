import os
import re
import unittest
from decimal import Decimal
from urllib.parse import parse_qs, urlparse
from unittest.mock import patch

import dotenv

with patch.object(dotenv, "load_dotenv"), patch.dict(
    os.environ,
    {
        "AUTOMATCH_ENV": "test",
        "AUTOMATCH_SECRET_KEY": "test-only-public-browsing-key",
    },
):
    import app as automatch


class FakeResult:
    def __init__(self, row=None, rows=None):
        self.row = row
        self.rows = rows

    def fetchone(self):
        return self.row

    def fetchall(self):
        return self.rows or []


class FakeDatabase:
    def __init__(self, vehicle, photos, user=None, inserted_user_id=42):
        self.vehicle = vehicle
        self.photos = photos
        self.user = user
        self.inserted_user_id = inserted_user_id
        self.queries = []

    def __enter__(self):
        return self

    def __exit__(self, exception_type, exception, traceback):
        return False

    def execute(self, query, params=()):
        normalized = " ".join(query.split())
        self.queries.append((normalized, params))

        if normalized.startswith(
            "SELECT v.id, v.brand, v.model, v.year, v.price,"
        ):
            return FakeResult({
                "id": self.vehicle["id"],
                "brand": self.vehicle["brand"],
                "model": self.vehicle["model"],
                "year": self.vehicle["year"],
                "price": self.vehicle["price"],
                "province": self.vehicle["province"],
                "neighborhood": self.vehicle["neighborhood"],
                "location": self.vehicle["location"],
                "photo": self.photos[0]["filename"],
            })

        if normalized.startswith(
            "SELECT v.id, v.brand, v.model, v.neighborhood"
        ):
            row = {
                **self.vehicle,
                "photo": self.photos[0]["filename"],
                "is_featured_active": 0,
            }
            return FakeResult(rows=[row])

        if normalized.startswith("SELECT * FROM vehicles"):
            return FakeResult(self.vehicle)

        if normalized.startswith("SELECT 1 FROM favorites"):
            return FakeResult()

        if normalized.startswith("SELECT filename FROM vehicle_photos"):
            return FakeResult(rows=self.photos)

        if normalized.startswith(
            "SELECT id, filename, is_cover FROM vehicle_photos"
        ):
            return FakeResult(rows=[
                {
                    "id": index,
                    "filename": photo["filename"],
                    "is_cover": index == 1,
                }
                for index, photo in enumerate(self.photos, start=1)
            ])

        if normalized.startswith("SELECT * FROM users WHERE email"):
            return FakeResult(self.user)

        if normalized.startswith("INSERT INTO users"):
            return FakeResult({"id": self.inserted_user_id})

        raise AssertionError("Unexpected database query: {}".format(normalized))


class PublicBrowsingTests(unittest.TestCase):
    def setUp(self):
        self.vehicle = {
            "id": 27,
            "user_id": 9,
            "status": "published",
            "category": "Auto",
            "brand": "Toyota",
            "model": "Corolla",
            "year": 2020,
            "price": 20000000,
            "province": "Córdoba",
            "location": "Córdoba, Nueva Córdoba",
            "neighborhood": "Nueva Córdoba",
            "kilometers": 50000,
            "description": "Muy buen estado",
            "accepts_trade": True,
            "trade_details": "Moto de menor valor",
            "contact_name": "Ana Vendedora",
            "whatsapp": "+54 9 351 123 4567",
            "email": "ana@example.test",
        }
        self.photos = [
            {"filename": "corolla-portada.jpg"},
            {"filename": "corolla-lateral.jpg"},
        ]
        self.user = {
            "id": 9,
            "name": "Ana Vendedora",
            "email": "ana@example.test",
            "phone": "+54 9 351 123 4567",
            "role": "user",
            "password_hash": automatch.generate_password_hash("password123"),
        }
        self.database = FakeDatabase(
            self.vehicle,
            self.photos,
            user=self.user,
        )
        self.client = automatch.app.test_client()
        self.patches = [
            patch.object(automatch, "get_db", return_value=self.database),
            patch.object(automatch, "current_user", return_value=None),
            patch.object(automatch, "registrar_visita"),
            patch.object(
                automatch,
                "get_public_photo_url",
                side_effect=lambda filename: (
                    "https://storage.example.test/" + filename
                ),
            ),
        ]
        for item in self.patches:
            item.start()

    def tearDown(self):
        for item in reversed(self.patches):
            item.stop()

    def test_price_formatter_uses_argentine_separators_and_two_decimals(self):
        examples = (
            (Decimal("5000000"), "5.000.000,00"),
            (Decimal("850000.50"), "850.000,50"),
            (Decimal("120000"), "120.000,00"),
        )
        for value, expected in examples:
            with self.subTest(value=value):
                self.assertEqual(automatch.precio_es(value), expected)

    def test_guest_can_browse_catalog_and_full_vehicle_details(self):
        catalog = self.client.get("/")

        self.assertEqual(catalog.status_code, 200)
        self.assertIn(b'href="/vehiculo/27"', catalog.data)
        self.assertIn(b"Toyota Corolla", catalog.data)
        self.assertIn(b"$20.000.000,00", catalog.data)
        self.assertIn("Nueva Córdoba".encode("utf-8"), catalog.data)
        self.assertIn(b"2020", catalog.data)
        self.assertIn(b"50,000 km", catalog.data)

        detail = self.client.get("/vehiculo/27")

        self.assertEqual(detail.status_code, 200)
        self.assertIn(b"Toyota Corolla", detail.data)
        self.assertIn(b"$20.000.000,00", detail.data)
        self.assertIn("Córdoba".encode("utf-8"), detail.data)
        self.assertIn("Nueva Córdoba".encode("utf-8"), detail.data)
        self.assertIn(b"Muy buen estado", detail.data)
        self.assertIn(b"Moto de menor valor", detail.data)
        self.assertIn(b"corolla-portada.jpg", detail.data)
        self.assertIn(b"corolla-lateral.jpg", detail.data)
        self.assertIn("Ampliar fotografía 1".encode("utf-8"), detail.data)
        self.assertIn(b"https://wa.me/5493511234567", detail.data)

    def test_guest_can_open_photos_and_share_a_publication(self):
        detail = self.client.get("/vehiculo/27")
        self.assertEqual(detail.status_code, 200)
        self.assertIn(b"/uploads/corolla-portada.jpg", detail.data)
        self.assertIn(b"/uploads/corolla-lateral.jpg", detail.data)

        photo = self.client.get("/uploads/corolla-portada.jpg")
        self.assertEqual(photo.status_code, 302)
        self.assertEqual(
            photo.headers["Location"],
            "https://storage.example.test/corolla-portada.jpg",
        )

        catalog = self.client.get("/")
        share_link = re.search(
            rb'href="(https://wa\.me/\?text=[^"]+)"',
            catalog.data,
        ).group(1).decode("ascii")
        message = parse_qs(urlparse(share_link).query)["text"][0]
        self.assertEqual(
            message,
            "Toyota Corolla 2020 - $20.000.000,00 - "
            "Córdoba, Nueva Córdoba "
            "https://localhost/compartir/vehiculo/27",
        )
        self.assertNotIn("50,000", message)
        self.assertNotIn("Mira", message)
        self.assertNotIn("Mirá", message)
        self.assertIn(b"compartir", catalog.data)

        shared = self.client.get("/compartir/vehiculo/27")
        self.assertEqual(shared.status_code, 200)
        self.assertIn(b'href="/vehiculo/27"', shared.data)
        self.assertIn(b"Ver publicaci", shared.data)
        self.assertIn(
            b'<meta property="og:url" content="https://localhost/compartir/vehiculo/27">',
            shared.data,
        )
        self.assertIn(
            b'<meta property="og:image" content="https://storage.example.test/corolla-portada.jpg">',
            shared.data,
        )
        self.assertIn(
            'content="Toyota Corolla 2020 - $20.000.000,00 - Córdoba, Nueva Córdoba"'.encode("utf-8"),
            shared.data,
        )
        self.assertNotIn(b"Mira esta publicacion", shared.data)
        self.assertNotIn(b"50,000 km", shared.data)
        self.assertNotIn(b"Ingresar para ver los detalles", shared.data)

    def test_guest_is_sent_to_publication_registration(self):
        response = self.client.get("/publicar", follow_redirects=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn(
            "¡Creá tu cuenta para publicar! Para publicar un vehículo en "
            "AUTOMATCHCBA, primero necesitás registrarte.".encode("utf-8"),
            response.data,
        )
        self.assertIn(b'name="name"', response.data)
        self.assertIn(b'name="email"', response.data)
        self.assertIn(b'name="phone"', response.data)
        self.assertIn(b'name="password"', response.data)
        self.assertIn("Iniciá sesión".encode("utf-8"), response.data)
        self.assertIn(b"/ingresar?next=/publicar", response.data)

    def test_guest_post_cannot_reach_publication_form_handler(self):
        response = self.client.post(
            "/publicar",
            data={"brand": "Unauthorized"},
        )

        self.assertEqual(response.status_code, 302)
        self.assertIn("/registro?next=/publicar", response.headers["Location"])
        self.assertFalse(any(
            query.startswith("INSERT INTO vehicles")
            for query, _params in self.database.queries
        ))

    def test_new_account_can_continue_directly_to_publication_form(self):
        self.client.get("/publicar", follow_redirects=True)
        with self.client.session_transaction() as flask_session:
            csrf_token = flask_session["form_csrf_token"]

        response = self.client.post(
            "/registro?next=%2Fpublicar",
            data={
                "csrf_token": csrf_token,
                "name": "Nueva Persona",
                "email": "nueva@example.test",
                "phone": "+54 9 351 111 2222",
                "password": "password123",
                "password_confirmation": "password123",
            },
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/publicar")
        with self.client.session_transaction() as flask_session:
            self.assertEqual(flask_session["user_id"], 42)

        form = self.client.get("/publicar")
        self.assertEqual(form.status_code, 200)
        self.assertIn(b"Public", form.data)

    def test_existing_user_login_returns_to_publish_without_registering_again(self):
        self.client.get("/ingresar?next=%2Fpublicar")
        with self.client.session_transaction() as flask_session:
            csrf_token = flask_session["form_csrf_token"]

        response = self.client.post(
            "/ingresar?next=%2Fpublicar",
            data={
                "csrf_token": csrf_token,
                "email": self.user["email"],
                "password": "password123",
            },
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/publicar")
        self.assertFalse(any(
            query.startswith("INSERT INTO users")
            for query, _params in self.database.queries
        ))
        self.assertEqual(self.client.get("/publicar").status_code, 200)

    def test_owner_can_still_open_own_publication_for_editing(self):
        owner_patch = patch.object(
            automatch,
            "current_user",
            return_value=self.user,
        )
        owner_patch.start()
        self.addCleanup(owner_patch.stop)
        with self.client.session_transaction() as flask_session:
            flask_session["user_id"] = self.user["id"]

        response = self.client.get("/vehiculo/27/editar")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Toyota", response.data)
        self.assertIn(b"Fotograf", response.data)


if __name__ == "__main__":
    unittest.main()
