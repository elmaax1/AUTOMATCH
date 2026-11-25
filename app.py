from pathlib import Path
from datetime import timedelta
import os
import boto3
import secrets
import hashlib
import hmac
from decimal import Decimal, InvalidOperation
import psycopg
from psycopg.rows import dict_row
import requests
from functools import wraps
from uuid import uuid4

from flask import Flask, render_template, request, redirect, url_for, flash, abort, session
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
from PIL import Image, UnidentifiedImageError

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")
UPLOAD_DIR = BASE_DIR / "uploads"
UPLOAD_DIR.mkdir(exist_ok=True)
SECRET_FILE = BASE_DIR / ".automatch_secret"

app = Flask(__name__)

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.getenv("AUTOMATCH_HTTPS", "0") == "1",
)
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=30)
app.config["MAX_CONTENT_LENGTH"] = 8 * 1024 * 1024
app.config["UPLOAD_FOLDER"] = str(UPLOAD_DIR)

# La clave se conserva entre reinicios. No compartas el archivo .automatch_secret.
if os.environ.get("AUTOMATCH_SECRET_KEY"):
    app.secret_key = os.environ["AUTOMATCH_SECRET_KEY"]
else:
    if not SECRET_FILE.exists():
        SECRET_FILE.write_text(secrets.token_hex(32), encoding="utf-8")
    app.secret_key = SECRET_FILE.read_text(encoding="utf-8").strip()

ALLOWED_EXTENSIONS = {"jpg", "jpeg", "png", "webp"}

PROVINCES = [
    "Buenos Aires",
    "Catamarca",
    "Chaco",
    "Chubut",
    "Ciudad Autonoma de Buenos Aires (CABA)",
    "Cordoba",
    "Corrientes",
    "Entre Rios",
    "Formosa",
    "Jujuy",
    "La Pampa",
    "La Rioja",
    "Mendoza",
    "Misiones",
    "Neuquen",
    "Rio Negro",
    "Salta",
    "San Juan",
    "San Luis",
    "Santa Cruz",
    "Santa Fe",
    "Santiago del Estero",
    "Tierra del Fuego, Antartida e Islas del Atlantico Sur",
    "Tucuman",
]



def get_s3_client():
    variables = [
        "SUPABASE_S3_ENDPOINT_URL",
        "SUPABASE_S3_REGION",
        "SUPABASE_S3_ACCESS_KEY_ID",
        "SUPABASE_S3_SECRET_ACCESS_KEY",
        "SUPABASE_STORAGE_BUCKET",
    ]

    faltantes = [nombre for nombre in variables if not os.environ.get(nombre)]
    if faltantes:
        raise RuntimeError(
            "Faltan variables de configuraciÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â³n de Supabase Storage: "
            + ", ".join(faltantes)
        )

    return boto3.client(
        "s3",
        endpoint_url=os.environ["SUPABASE_S3_ENDPOINT_URL"],
        region_name=os.environ["SUPABASE_S3_REGION"],
        aws_access_key_id=os.environ["SUPABASE_S3_ACCESS_KEY_ID"],
        aws_secret_access_key=os.environ["SUPABASE_S3_SECRET_ACCESS_KEY"],
    )



def upload_photo_to_storage(photo, filename, tipo_mime):
    bucket = os.environ["SUPABASE_STORAGE_BUCKET"]
    photo.stream.seek(0)

    get_s3_client().upload_fileobj(
        photo.stream,
        bucket,
        filename,
        ExtraArgs={
            "ContentType": tipo_mime
        },
    )


def delete_photo_from_storage(filename):
    bucket = os.environ["SUPABASE_STORAGE_BUCKET"]

    get_s3_client().delete_object(
        Bucket=bucket,
        Key=filename
    )



def get_public_photo_url(filename):
    from urllib.parse import quote

    base = os.environ["SUPABASE_URL"].rstrip("/")
    bucket = os.environ["SUPABASE_STORAGE_BUCKET"]
    nombre = quote(filename, safe="")

    return f"{base}/storage/v1/object/public/{bucket}/{nombre}"


def get_db():
    url = os.environ.get("DATABASE_URL")
    if not url:
        raise RuntimeError("No se encontrÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â³ DATABASE_URL en la configuraciÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â³n.")
    return psycopg.connect(url, row_factory=dict_row)



def current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None
    with get_db() as db:
        return db.execute(
            "SELECT id, name, email, role FROM users WHERE id = %s", (user_id,)
        ).fetchone()


@app.context_processor
def inject_user():
    return {
        "usuario_actual": current_user(),
        "csrf_token": get_form_csrf_token()
    }


def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if not session.get("user_id"):
            flash("Para continuar, primero tenÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â©s que ingresar a tu cuenta.", "error")
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped_view


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def validar_fotografia(photo, filename):
    if not filename or not allowed_file(filename):
        return None

    formatos = {
        "jpg": ("JPEG", "image/jpeg"),
        "jpeg": ("JPEG", "image/jpeg"),
        "png": ("PNG", "image/png"),
        "webp": ("WEBP", "image/webp"),
    }

    extension = filename.rsplit(".", 1)[1].lower()
    formato_esperado, tipo_mime = formatos[extension]

    try:
        import warnings

        photo.stream.seek(0)

        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)

            with Image.open(photo.stream) as imagen:
                if imagen.format != formato_esperado:
                    return None
                imagen.verify()

        return tipo_mime

    except (
        UnidentifiedImageError,
        OSError,
        ValueError,
        Image.DecompressionBombError,
        Image.DecompressionBombWarning,
    ):
        return None

    finally:
        photo.stream.seek(0)



_visit_table_ready = False

def registrar_visita():
    global _visit_table_ready

    with get_db() as db:
        if not _visit_table_ready:
            db.execute("""
                CREATE TABLE IF NOT EXISTS site_visits (
                    id BIGSERIAL PRIMARY KEY,
                    visited_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
            """)
            _visit_table_ready = True

        user_id = session.get("user_id")
        if user_id:
            user = db.execute(
                "SELECT role FROM users WHERE id = %s",
                (user_id,)
            ).fetchone()
            if user and user["role"] == "admin":
                return

        db.execute("INSERT INTO site_visits DEFAULT VALUES")




@app.route("/")
def index():
    registrar_visita()
    query = request.args.get("q", "").strip()
    category = request.args.get("category", "").strip()
    max_price = request.args.get("max_price", "").strip()
    province = request.args.get("province", "").strip()
    if province not in PROVINCES:
        province = ""

    if session.get("user_id"):
        sql = """
            SELECT v.*,
            CASE WHEN v.featured = 1 AND v.featured_until IS NOT NULL
                 AND v.featured_until > CURRENT_TIMESTAMP
                 THEN 1 ELSE 0 END AS is_featured_active,
            (SELECT filename FROM vehicle_photos p
             WHERE p.vehicle_id = v.id ORDER BY p.is_cover DESC, p.id LIMIT 1) AS photo,
            EXISTS (
                SELECT 1 FROM favorites f
                WHERE f.vehicle_id = v.id
                  AND f.user_id = %s
            ) AS is_favorite
            FROM vehicles v
            WHERE v.status = 'published'
        """
        params = [session.get("user_id")]
        if province:
            sql += " AND v.province = %s"
            params.append(province)
        if query:
            sql += " AND (v.brand ILIKE %s OR v.model ILIKE %s OR v.location ILIKE %s)"
            term = f"%{query}%"
            params.extend([term, term, term])
        if category:
            sql += " AND v.category = %s"
            params.append(category)
        if max_price:
            try:
                sql += " AND v.price <= %s"
                params.append(float(max_price))
            except ValueError:
                flash("El precio mÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¡ximo debe ser un nÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Âºmero.", "error")
        sql += " ORDER BY CASE WHEN v.featured = 1 AND v.featured_until > CURRENT_TIMESTAMP THEN 1 ELSE 0 END DESC, v.created_at DESC" 
        with get_db() as db:
            vehicles = db.execute(sql, params).fetchall()
        return render_template(
            "index.html", vehicles=vehicles, query=query,
            selected_category=category, max_price=max_price,
            selected_province=province, provinces=PROVINCES
        )

    # Visitantes: la consulta obtiene los datos publicos de los vehiculos.
    sql = """
        SELECT v.id, v.brand, v.model, v.neighborhood, v.province, v.location, v.price,
        CASE WHEN v.featured = 1 AND v.featured_until IS NOT NULL
             AND v.featured_until > CURRENT_TIMESTAMP
             THEN 1 ELSE 0 END AS is_featured_active,
        (SELECT filename FROM vehicle_photos p
             WHERE p.vehicle_id = v.id ORDER BY p.is_cover DESC, p.id LIMIT 1) AS photo
        FROM vehicles v
        WHERE v.status = 'published'
    """
    params = []
    if province:
        sql += " AND v.province = %s"
        params.append(province)
    if query:
        sql += " AND (v.brand ILIKE %s OR v.model ILIKE %s)"
        term = f"%{query}%"
        params.extend([term, term])
    sql += " ORDER BY CASE WHEN v.featured = 1 AND v.featured_until > CURRENT_TIMESTAMP THEN 1 ELSE 0 END DESC, v.created_at DESC" 
    with get_db() as db:
        vehicles = db.execute(sql, params).fetchall()
    return render_template(
        "index.html", vehicles=vehicles, query=query,
        selected_category="", max_price="",
        selected_province=province, provinces=PROVINCES
    )



@app.route("/compartir/vehiculo/<int:vehicle_id>")
def share_vehicle(vehicle_id):
    with get_db() as db:
        vehicle = db.execute(
            """
            SELECT v.id, v.brand, v.model, v.price,
                   (SELECT filename FROM vehicle_photos p
                    WHERE p.vehicle_id = v.id
                    ORDER BY p.is_cover DESC, p.id LIMIT 1) AS photo
            FROM vehicles v
            WHERE v.id = %s AND v.status = 'published'
            """,
            (vehicle_id,)
        ).fetchone()

    if vehicle is None:
        abort(404)

    if vehicle["photo"]:
        image_url = get_public_photo_url(vehicle["photo"])
    else:
        image_url = url_for(
            "static",
            filename="icono-automatchcba-preview.jpg",
            _external=True,
            _scheme="https"
        )

    return render_template(
        "share_vehicle.html",
        vehicle=vehicle,
        image_url=image_url
    )



def get_form_csrf_token():
    token = session.get("form_csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["form_csrf_token"] = token
    return token


def verify_form_csrf():
    token = session.get("form_csrf_token")
    enviado = request.form.get("csrf_token", "")
    if not token or not secrets.compare_digest(token, enviado):
        abort(400)

@app.route("/vehiculo/<int:vehicle_id>/favorito", methods=["POST"])
@login_required
def toggle_favorite(vehicle_id):
    verify_form_csrf()
    user_id = session.get("user_id")

    with get_db() as db:
        vehicle = db.execute(
            "SELECT id FROM vehicles WHERE id = %s AND status = 'published'",
            (vehicle_id,)
        ).fetchone()

        if not vehicle:
            abort(404)

        existing = db.execute(
            "SELECT 1 FROM favorites WHERE user_id = %s AND vehicle_id = %s",
            (user_id, vehicle_id)
        ).fetchone()

        if existing:
            db.execute(
                "DELETE FROM favorites WHERE user_id = %s AND vehicle_id = %s",
                (user_id, vehicle_id)
            )
            flash("Vehiculo eliminado de favoritos.", "success")
        else:
            db.execute(
                "INSERT INTO favorites (user_id, vehicle_id) VALUES (%s, %s) ON CONFLICT DO NOTHING",
                (user_id, vehicle_id)
            )
            flash("Vehiculo guardado en favoritos.", "success")

    destino = request.form.get("next", "")
    if destino.startswith("/") and not destino.startswith("//"):
        return redirect(destino)
    return redirect(url_for("index"))

@app.route("/favoritos")
@login_required
def favorites():
    user_id = session.get("user_id")

    with get_db() as db:
        vehicles = db.execute(
            """
            SELECT v.*,
                CASE WHEN v.featured = 1
                     AND v.featured_until IS NOT NULL
                     AND v.featured_until > CURRENT_TIMESTAMP
                     THEN 1 ELSE 0 END AS is_featured_active,
                (SELECT filename FROM vehicle_photos p
                 WHERE p.vehicle_id = v.id
                 ORDER BY p.is_cover DESC, p.id LIMIT 1) AS photo
            FROM favorites f
            JOIN vehicles v ON v.id = f.vehicle_id
            WHERE f.user_id = %s
              AND v.status = 'published'
            ORDER BY f.created_at DESC
            """,
            (user_id,)
        ).fetchall()

    return render_template("favorites.html", vehicles=vehicles)

@app.route("/registro", methods=["GET", "POST"])
def register():
    if session.get("user_id"):
        return redirect(url_for("index"))
    if request.method == "POST":
        verify_form_csrf()
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        phone = request.form.get("phone", "").strip()
        password = request.form.get("password", "")
        confirmation = request.form.get("password_confirmation", "")

        if not name or not email or not phone or not password:
            flash("CompletÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¡ todos los campos obligatorios.", "error")
        elif len(password) < 8:
            flash("La contraseÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â±a debe tener al menos 8 caracteres.", "error")
        elif password != confirmation:
            flash("Las contraseÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â±as no coinciden.", "error")
        else:
            try:
                with get_db() as db:
                    cursor = db.execute(
                        "INSERT INTO users (name, email, phone, password_hash) VALUES (%s, %s, %s, %s) RETURNING id",
                        (name, email, phone, generate_password_hash(password))
                    )
                    session.clear()
                    session["user_id"] = cursor.fetchone()["id"]
                flash("Tu cuenta fue creada correctamente. ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¡Bienvenido a AUTOMATCH!", "success")
                return redirect(url_for("index"))
            except psycopg.IntegrityError:
                flash("Ya existe una cuenta registrada con ese correo electrÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â³nico.", "error")
    return render_template("register.html", csrf_token=get_form_csrf_token())


@app.route("/ingresar", methods=["GET", "POST"])
def login():
    if session.get("user_id"):
        return redirect(url_for("index"))
    if request.method == "POST":
        verify_form_csrf()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        with get_db() as db:
            user = db.execute("SELECT * FROM users WHERE email = %s", (email,)).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            session.permanent = request.form.get("remember_me") == "on"
            destination = request.args.get("next", "")
            if not destination.startswith("/") or destination.startswith("//"):
                destination = url_for("index")
            return redirect(destination)
        flash("El correo electrÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â³nico o la contraseÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â±a son incorrectos.", "error")
    return render_template("login.html", csrf_token=get_form_csrf_token())


@app.route("/salir")
@login_required
def logout():
    session.clear()
    flash("Cerraste tu sesiÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â³n correctamente.", "success")
    return redirect(url_for("index"))


@app.route("/publicar", methods=["GET", "POST"])
@login_required
def publish():
    if request.method == "POST":
        verify_form_csrf()
        province = request.form.get("province", "").strip()
        neighborhood = request.form.get("neighborhood", "").strip()

        if province not in PROVINCES:
            flash("Selecciona una provincia valida.", "error")
            return redirect(url_for("publish"))

        location = f"{province}, {neighborhood}" if neighborhood else province

        required = ["category", "brand", "model", "year", "price"]
        missing = [field for field in required if not request.form.get(field, "").strip()]
        if missing:
            flash("CompletÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¡ todos los campos obligatorios.", "error")
            return redirect(url_for("publish"))

        try:
            year = int(request.form["year"])
            price = float(request.form["price"])
            kilometers = int(request.form.get("kilometers") or 0)
            if year < 1900 or year > 2100 or price <= 0 or kilometers < 0:
                raise ValueError
        except ValueError:
            flash("RevisÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¡ el aÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â±o, el precio y los kilÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â³metros.", "error")
            return redirect(url_for("publish"))

        fotografias = []

        for photo in request.files.getlist("photos"):
            if photo and photo.filename:
                tipo_mime = validar_fotografia(photo, photo.filename)

                if not tipo_mime:
                    flash(
                        "Una o mas fotografias no son validas. "
                        "Usa imagenes JPG, PNG o WEBP autenticas.",
                        "error"
                    )
                    return redirect(url_for("publish"))

                fotografias.append((photo, tipo_mime))

        accepts_trade = 1 if request.form.get("accepts_trade") == "on" else 0
        archivos_subidos = []

        try:
            with get_db() as db:
                user = db.execute(
                    "SELECT name, email, phone FROM users WHERE id = %s",
                    (session["user_id"],)
                ).fetchone()

                if not user:
                    flash("No se pudieron obtener los datos de tu cuenta.", "error")
                    return redirect(url_for("publish"))

                cursor = db.execute("""
                    INSERT INTO vehicles
                    (category, brand, model, year, kilometers, price, province, location, neighborhood,
                     description, contact_name, whatsapp, email, accepts_trade,
                     trade_details, user_id)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING id
                """, (
                    request.form["category"].strip(),
                    request.form["brand"].strip(),
                    request.form["model"].strip(),
                    year, kilometers, price,
                    province,
                    location,
                    neighborhood,
                    request.form.get("description", "").strip(),
                    user["name"],
                    user["phone"],
                    user["email"],
                    accepts_trade,
                    request.form.get("trade_details", "").strip(),
                    session["user_id"]
                ))
                vehicle_id = cursor.fetchone()["id"]

                for indice, (photo, tipo_mime) in enumerate(fotografias):
                    extension = photo.filename.rsplit(".", 1)[1].lower()
                    filename = secure_filename(f"{uuid4().hex}.{extension}")

                    archivos_subidos.append(filename)
                    upload_photo_to_storage(photo, filename, tipo_mime)

                    db.execute(
                        """INSERT INTO vehicle_photos
                           (vehicle_id, filename, is_cover)
                           VALUES (%s, %s, %s)""",
                        (vehicle_id, filename, indice == 0)
                    )

        except Exception:
            app.logger.exception("Error al publicar vehiculo o subir fotografias.")

            for filename in archivos_subidos:
                try:
                    delete_photo_from_storage(filename)
                except Exception:
                    app.logger.exception(
                        "No se pudo eliminar la fotografia %s de Supabase.",
                        filename
                    )

            flash(
                "No se pudo completar la publicacion. Intenta nuevamente.",
                "error"
            )
            return redirect(url_for("publish"))

        flash("ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¡Tu vehÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â­culo ya estÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¡ publicado en AUTOMATCH!", "success")
        return redirect(url_for("vehicle_detail", vehicle_id=vehicle_id))
    return render_template(
        "publish.html",
        csrf_token=get_form_csrf_token(),
        provinces=PROVINCES
    )


@app.route("/vehiculo/<int:vehicle_id>/editar", methods=["GET", "POST"])
@login_required
def vehicle_edit(vehicle_id):
    user = current_user()

    if not user:
        abort(403)

    with get_db() as db:
        vehicle = db.execute(
            "SELECT * FROM vehicles WHERE id = %s",
            (vehicle_id,)
        ).fetchone()

    if not vehicle:
        abort(404)

    if user["role"] != "admin" and vehicle["user_id"] != user["id"]:
        abort(403)

    if request.method == "POST":
        verify_form_csrf()

        province = request.form.get("province", "").strip()
        neighborhood = request.form.get("neighborhood", "").strip()

        if province and province not in PROVINCES:
            flash("Selecciona una provincia valida.", "error")
            return redirect(url_for("vehicle_edit", vehicle_id=vehicle_id))

        location = (
            f"{province}, {neighborhood}" if neighborhood
            else province
        ) if province else vehicle["location"]

        required = [
            "category", "brand", "model", "year", "price",
            "contact_name", "whatsapp"
        ]

        missing = [
            field for field in required
            if not request.form.get(field, "").strip()
        ]

        if missing:
            flash("Completa todos los campos obligatorios.", "error")
            return redirect(url_for("vehicle_edit", vehicle_id=vehicle_id))

        try:
            year = int(request.form["year"])
            price = float(request.form["price"])
            kilometers = int(request.form.get("kilometers") or 0)

            if year < 1900 or year > 2100 or price <= 0 or kilometers < 0:
                raise ValueError

        except ValueError:
            flash("Revisa el año, el precio y los kilómetros.", "error")
            return redirect(url_for("vehicle_edit", vehicle_id=vehicle_id))

        fotografias = []

        for photo in request.files.getlist("photos"):
            if photo and photo.filename:
                original_name = photo.filename.replace("\\", "/").split("/")[-1]
                tipo_mime = validar_fotografia(photo, original_name)

                if not tipo_mime:
                    flash(
                        "Una fotografía no es válida. Usa imágenes JPG, PNG o WEBP.",
                        "error"
                    )
                    return redirect(url_for("vehicle_edit", vehicle_id=vehicle_id))

                fotografias.append((photo, original_name, tipo_mime))

        cover_value = request.form.get("cover_photo_id", "").strip()
        try:
            selected_cover_id = int(cover_value) if cover_value else None
            if selected_cover_id is not None and selected_cover_id <= 0:
                raise ValueError
        except ValueError:
            flash("La foto de portada seleccionada no es válida.", "error")
            return redirect(url_for("vehicle_edit", vehicle_id=vehicle_id))

        try:
            remove_ids = set()

            for value in request.form.getlist("remove_photo_ids"):
                try:
                    photo_id = int(value)
                except ValueError:
                    abort(400)

                if photo_id > 0:
                    remove_ids.add(photo_id)

            archivos_subidos = []
            archivos_eliminados = []

            accepts_trade = (
                1 if request.form.get("accepts_trade") == "on" else 0
            )

            try:
                with get_db() as db:
                    if selected_cover_id is not None:
                        selected_photo = db.execute("""
                            SELECT id
                            FROM vehicle_photos
                            WHERE id = %s AND vehicle_id = %s
                        """, (selected_cover_id, vehicle_id)).fetchone()

                        if not selected_photo:
                            flash("La foto de portada no pertenece a esta publicación.", "error")
                            return redirect(url_for("vehicle_edit", vehicle_id=vehicle_id))

                        if selected_cover_id in remove_ids:
                            selected_cover_id = None

                    db.execute("""
                        UPDATE vehicles SET
                            category = %s,
                            brand = %s,
                            model = %s,
                            year = %s,
                            kilometers = %s,
                            price = %s,
                            province = %s,
                            location = %s,
                            neighborhood = %s,
                            description = %s,
                            contact_name = %s,
                            whatsapp = %s,
                            email = %s,
                            accepts_trade = %s,
                            trade_details = %s
                        WHERE id = %s
                    """, (
                        request.form["category"].strip(),
                        request.form["brand"].strip(),
                        request.form["model"].strip(),
                        year,
                        kilometers,
                        price,
                        province or vehicle["province"],
                        location,
                        neighborhood,
                        request.form.get("description", "").strip(),
                        request.form["contact_name"].strip(),
                        request.form["whatsapp"].strip(),
                        request.form.get("email", "").strip(),
                        accepts_trade,
                        request.form.get("trade_details", "").strip(),
                        vehicle_id
                    ))

                    for photo_id in remove_ids:
                        photo = db.execute("""
                            SELECT filename
                            FROM vehicle_photos
                            WHERE id = %s AND vehicle_id = %s
                        """, (photo_id, vehicle_id)).fetchone()

                        if photo:
                            db.execute(
                                "DELETE FROM vehicle_photos WHERE id = %s AND vehicle_id = %s",
                                (photo_id, vehicle_id)
                            )
                            archivos_eliminados.append(photo["filename"])

                    for photo, original_name, tipo_mime in fotografias:
                        extension = original_name.rsplit(".", 1)[1].lower()
                        filename = secure_filename(
                            f"{uuid4().hex}.{extension}"
                        )

                        archivos_subidos.append(filename)

                        upload_photo_to_storage(
                            photo, filename, tipo_mime
                        )

                        db.execute("""
                            INSERT INTO vehicle_photos
                                (vehicle_id, filename, is_cover)
                            VALUES (%s, %s, FALSE)
                        """, (vehicle_id, filename))

                    if selected_cover_id is not None:
                        db.execute("""
                            UPDATE vehicle_photos
                            SET is_cover = FALSE
                            WHERE vehicle_id = %s
                        """, (vehicle_id,))

                        db.execute("""
                            UPDATE vehicle_photos
                            SET is_cover = TRUE
                            WHERE id = %s AND vehicle_id = %s
                        """, (selected_cover_id, vehicle_id))
                    else:
                        portada_actual = db.execute("""
                            SELECT id
                            FROM vehicle_photos
                            WHERE vehicle_id = %s AND is_cover = TRUE
                            LIMIT 1
                        """, (vehicle_id,)).fetchone()

                        if not portada_actual:
                            primera_foto = db.execute("""
                                SELECT id
                                FROM vehicle_photos
                                WHERE vehicle_id = %s
                                ORDER BY id
                                LIMIT 1
                            """, (vehicle_id,)).fetchone()

                            if primera_foto:
                                db.execute("""
                                    UPDATE vehicle_photos
                                    SET is_cover = FALSE
                                    WHERE vehicle_id = %s
                                """, (vehicle_id,))

                                db.execute("""
                                    UPDATE vehicle_photos
                                    SET is_cover = TRUE
                                    WHERE id = %s AND vehicle_id = %s
                                """, (primera_foto["id"], vehicle_id))

            except Exception:
                for filename in archivos_subidos:
                    try:
                        delete_photo_from_storage(filename)
                    except Exception:
                        app.logger.exception(
                            "No se pudo limpiar la foto nueva %s.",
                            filename
                        )
                raise

            for filename in archivos_eliminados:
                if not filename or Path(filename).name != filename:
                    continue

                with get_db() as db:
                    references = db.execute("""
                        SELECT COUNT(*) AS count
                        FROM vehicle_photos
                        WHERE filename = %s
                    """, (filename,)).fetchone()["count"]

                if references == 0:
                    try:
                        delete_photo_from_storage(filename)
                    except Exception:
                        app.logger.exception(
                            "No se pudo eliminar la foto %s de Supabase.",
                            filename
                        )

        except Exception:
            app.logger.exception(
                "Error al editar el vehículo %s.",
                vehicle_id
            )
            flash(
                "No se pudo completar la edición. Intenta nuevamente.",
                "error"
            )
            return redirect(url_for("vehicle_edit", vehicle_id=vehicle_id))

        flash("Publicación actualizada correctamente.", "success")
        return redirect(url_for("vehicle_detail", vehicle_id=vehicle_id))

    with get_db() as db:
        photos = db.execute("""
            SELECT id, filename, is_cover
            FROM vehicle_photos
            WHERE vehicle_id = %s
            ORDER BY is_cover DESC, id
        """, (vehicle_id,)).fetchall()

    return render_template(
        "edit_vehicle.html",
        vehicle=vehicle,
        photos=photos,
        csrf_token=get_form_csrf_token(),
        provinces=PROVINCES
    )

@app.route("/uploads/<path:filename>")
def uploaded_file(filename):
    if not filename or "/" in filename or "\\" in filename or filename in {".", ".."}:
        abort(404)

    return redirect(get_public_photo_url(filename))



@app.route("/vehiculo/<int:vehicle_id>/destacar", methods=["POST"])
@login_required
def vehicle_feature_payment(vehicle_id):
    user = current_user()

    token = session.get("feature_csrf_token")
    enviado = request.form.get("csrf_token", "")

    if not token or not secrets.compare_digest(token, enviado):
        abort(400)

    with get_db() as db:
        vehicle = db.execute(
            "SELECT * FROM vehicles WHERE id = %s AND status = 'published'",
            (vehicle_id,)
        ).fetchone()

    if vehicle is None:
        abort(404)

    if user["role"] != "admin" and vehicle["user_id"] != user["id"]:
        abort(403)

    planes = {
        7: 2000,
        15: 4000,
        30: 7000
    }

    try:
        dias = int(request.form.get("plan_days", ""))
    except (TypeError, ValueError):
        abort(400)

    if dias not in planes:
        abort(400)

    access_token = os.getenv("MERCADOPAGO_ACCESS_TOKEN")
    if not access_token:
        flash("Falta configurar el acceso a Mercado Pago.", "error")
        return redirect(url_for("vehicle_detail", vehicle_id=vehicle_id))

    importe = planes[dias]
    referencia = "automatch-" + uuid4().hex
    clave_idempotencia = str(uuid4())

    with get_db() as db:
        db.execute("""
            INSERT INTO payments (
                user_id, vehicle_id, plan_days, amount,
                currency, payment_method, status,
                external_reference, idempotency_key
            )
            VALUES (%s, %s, %s, %s, 'ARS', 'mercadopago', 'pending', %s, %s)
        """, (
            user["id"], vehicle_id, dias, importe,
            referencia, clave_idempotencia
        ))

    datos = {
        "type": "online",
        "processing_mode": "manual",
        "total_amount": f"{importe:.2f}",
        "external_reference": referencia,
        "description": f"Destacado AUTOMATCH por {dias} dÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â­as",
        "payer": {
            "email": user["email"]
        },
        "items": [{
            "title": f"PublicaciÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â³n destacada por {dias} dÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â­as",
            "unit_price": f"{importe:.2f}",
            "quantity": 1
        }]
    }

    try:
        respuesta = requests.post(
            "https://api.mercadopago.com/v1/orders",
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json",
                "X-Idempotency-Key": clave_idempotencia
            },
            json=datos,
            timeout=30
        )

        resultado = respuesta.json()

        if not respuesta.ok:
            raise ValueError("Mercado Pago no aceptÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â³ la orden.")

        order_id = resultado.get("id")
        checkout_url = resultado.get("checkout_url")

        if not order_id or not checkout_url:
            raise ValueError("La respuesta no contiene los datos de pago.")

        with get_db() as db:
            db.execute("""
                UPDATE payments
                SET mp_order_id = %s, checkout_url = %s
                WHERE external_reference = %s
            """, (order_id, checkout_url, referencia))

        if not checkout_url.startswith("https://"):
            raise ValueError("La direcciÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â³n de pago no es segura.")

        return redirect(checkout_url)

    except (requests.RequestException, ValueError, KeyError):
        with get_db() as db:
            db.execute("""
                UPDATE payments
                SET status = 'error'
                WHERE external_reference = %s
            """, (referencia,))

        app.logger.exception("No se pudo crear la orden de Mercado Pago.")
        flash(
            "No pudimos iniciar el pago. RevisÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¡ la configuraciÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â³n e intentÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¡ nuevamente.",
            "error"
        )
        return redirect(url_for("vehicle_detail", vehicle_id=vehicle_id))



def verificar_firma_mercadopago(data_id):
    secreto = os.getenv("MERCADOPAGO_WEBHOOK_SECRET")
    firma = request.headers.get("x-signature", "")
    request_id = request.headers.get("x-request-id", "")

    if not secreto or not firma or not request_id or not data_id:
        return False

    partes = {}
    for elemento in firma.split(","):
        if "=" in elemento:
            clave, valor = elemento.split("=", 1)
            partes[clave.strip()] = valor.strip()

    timestamp = partes.get("ts")
    firma_recibida = partes.get("v1")

    if not timestamp or not firma_recibida:
        return False

    manifest = (
        f"id:{data_id};"
        f"request-id:{request_id};"
        f"ts:{timestamp};"
    )

    firma_calculada = hmac.new(
        secreto.encode("utf-8"),
        manifest.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()

    return hmac.compare_digest(firma_calculada, firma_recibida)


@app.route("/webhook/mercadopago", methods=["POST"])
def mercado_pago_webhook():
    secreto = os.getenv("MERCADOPAGO_WEBHOOK_SECRET")
    access_token = os.getenv("MERCADOPAGO_ACCESS_TOKEN")

    if not secreto or not access_token:
        app.logger.error("Falta configurar el secreto o Access Token de Mercado Pago.")
        return "", 503

    notificacion = request.get_json(silent=True) or {}
    data_id = request.args.get("data.id")
    body_id = (notificacion.get("data") or {}).get("id")

    if not data_id or str(body_id) != str(data_id):
        return "", 400

    if not verificar_firma_mercadopago(data_id):
        app.logger.warning("Firma de Webhook invÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¡lida.")
        return "", 401

    if notificacion.get("type") != "order":
        return "", 200

    if notificacion.get("live_mode") is not True:
        app.logger.warning("Se ignorÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â³ una notificaciÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â³n que no es de prueba.")
        return "", 200

    try:
        respuesta = requests.get(
            f"https://api.mercadopago.com/v1/orders/{data_id}",
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=20
        )
        if not respuesta.ok:
            app.logger.error("No se pudo consultar la orden notificada.")
            return "", 503

        orden = respuesta.json()

        if str(orden.get("id")) != str(data_id):
            return "", 200

        if (
            orden.get("status") != "processed"
            or orden.get("status_detail") != "accredited"
        ):
            return "", 200

        referencia = orden.get("external_reference")
        importe_orden = Decimal(str(orden.get("total_amount")))
        importe_pagado = Decimal(str(orden.get("total_paid_amount")))
        moneda = orden.get("currency") or orden.get("currency_id")

    except (requests.RequestException, ValueError, InvalidOperation, TypeError):
        app.logger.exception("Error al verificar la orden de Mercado Pago.")
        return "", 503

    planes = {
        7: Decimal("2000"),
        15: Decimal("4000"),
        30: Decimal("7000")
    }

    with get_db() as db:

        pago = db.execute("""
            SELECT id, vehicle_id, plan_days, amount, currency,
                   status, external_reference, mp_order_id
            FROM payments
            WHERE external_reference = %s AND mp_order_id = %s
            FOR UPDATE
        """, (referencia, str(data_id))).fetchone()

        if not pago:
            app.logger.warning("Orden sin pago asociado en AUTOMATCH.")
            return "", 200

        if pago["status"] != "pending":
            return "", 200

        dias = pago["plan_days"]

        if (
            dias not in planes
            or Decimal(str(pago["amount"])) != planes[dias]
            or importe_orden != planes[dias]
            or importe_pagado < planes[dias]
            or moneda != "ARS"
            or pago["currency"] != "ARS"
        ):
            app.logger.warning("Importe o moneda no coinciden con el pago.")
            return "", 200

        vehiculo = db.execute("""
            SELECT id
            FROM vehicles
            WHERE id = %s AND status = 'published'
            FOR UPDATE
        """, (pago["vehicle_id"],)).fetchone()

        if not vehiculo:
            app.logger.error(
                "Pago acreditado, pero el vehÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â­culo %s no existe o no estÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¡ publicado.",
                pago["vehicle_id"]
            )
            return "", 200

        vehiculo_actualizado = db.execute("""
            UPDATE vehicles
            SET featured = 1,
                featured_until =
                    GREATEST(
                        COALESCE(featured_until, CURRENT_TIMESTAMP),
                        CURRENT_TIMESTAMP
                    ) + (%s * INTERVAL '1 day')
            WHERE id = %s AND status = 'published'
            RETURNING featured, featured_until
        """, (dias, pago["vehicle_id"])).fetchone()

        if not vehiculo_actualizado or not vehiculo_actualizado["featured"]:
            app.logger.error("No se pudo activar el destacado del vehÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â­culo.")
            return "", 200

        vencimiento = vehiculo_actualizado["featured_until"]

        db.execute("""
            UPDATE payments
            SET status = 'approved',
                approved_at = CURRENT_TIMESTAMP,
                expires_at = %s
            WHERE id = %s AND status = 'pending'
        """, (vencimiento, pago["id"]))

    app.logger.info("Orden de Mercado Pago verificada: %s", data_id)
    return "", 200


@app.route("/vehiculo/<int:vehicle_id>")
@login_required
def vehicle_detail(vehicle_id):
    with get_db() as db:
        vehicle = db.execute(
            "SELECT * FROM vehicles WHERE id = %s AND status = 'published'",
            (vehicle_id,)
        ).fetchone()
        if vehicle is None:
            abort(404)

        is_favorite = db.execute(
            "SELECT 1 FROM favorites WHERE user_id = %s AND vehicle_id = %s",
            (session.get("user_id"), vehicle_id)
        ).fetchone() is not None

        photos = db.execute(
            """SELECT filename FROM vehicle_photos
               WHERE vehicle_id = %s
               ORDER BY is_cover DESC, id""",
            (vehicle_id,)
        ).fetchall()
    if not session.get("feature_csrf_token"):
        session["feature_csrf_token"] = secrets.token_urlsafe(32)

    return render_template(
        "vehicle.html",
        vehicle=vehicle,
        photos=photos,
        is_favorite=is_favorite,
        feature_csrf_token=session["feature_csrf_token"],
        csrf_token=get_form_csrf_token()
    )


@app.route("/vehiculo/<int:vehicle_id>/eliminar", methods=["POST"])
@login_required
def vehicle_delete(vehicle_id):
    verify_form_csrf()
    user = current_user()

    if not user:
        abort(403)

    with get_db() as db:
        vehicle = db.execute(
            "SELECT id, user_id FROM vehicles WHERE id = %s",
            (vehicle_id,)
        ).fetchone()

        if vehicle is None:
            abort(404)

        if user["role"] != "admin" and vehicle["user_id"] != user["id"]:
            abort(403)

        photos = db.execute(
            "SELECT filename FROM vehicle_photos WHERE vehicle_id = %s",
            (vehicle_id,)
        ).fetchall()

        filenames = [photo["filename"] for photo in photos]

        db.execute(
            "DELETE FROM vehicle_photos WHERE vehicle_id = %s",
            (vehicle_id,)
        )

        db.execute(
            "DELETE FROM vehicles WHERE id = %s",
            (vehicle_id,)
        )

    # Eliminar archivos solamente si ningun otro vehiculo los utiliza.
    for filename in filenames:
        if not filename or Path(filename).name != filename:
            continue

        with get_db() as db:
            references = db.execute(
                "SELECT COUNT(*) AS count FROM vehicle_photos WHERE filename = %s",
                (filename,)
            ).fetchone()["count"]

        if references == 0:
            try:
                get_s3_client().delete_object(
                    Bucket=os.environ["SUPABASE_STORAGE_BUCKET"],
                    Key=filename
                )
            except Exception:
                app.logger.exception(
                    "No se pudo eliminar la foto %s de Supabase Storage",
                    filename
                )

    flash("La publicacion fue eliminada correctamente.", "success")
    return redirect(url_for("index"))


@app.errorhandler(413)
def too_large(_error):
    flash("Las fotografÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â­as superan el lÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â­mite permitido de 8 MB por solicitud.", "error")
    return redirect(url_for("publish"))





def verificar_admin():
    user = current_user()
    if not user or user["role"] != "admin":
        abort(403)

    token = session.get("admin_csrf_token")
    enviado = request.form.get("csrf_token", "")

    if not token or not secrets.compare_digest(token, enviado):
        abort(400)


@app.route("/admin")
@login_required
def admin_dashboard():
    verificar_usuario = current_user()

    if not verificar_usuario or verificar_usuario["role"] != "admin":
        abort(403)

    registrar_visita()

    if not session.get("admin_csrf_token"):
        session["admin_csrf_token"] = secrets.token_urlsafe(32)

    with get_db() as db:
        total_users = db.execute(
            "SELECT COUNT(*) AS count FROM users"
        ).fetchone()["count"]

        total_vehicles = db.execute(
            "SELECT COUNT(*) AS count FROM vehicles"
        ).fetchone()["count"]

        published_vehicles = db.execute(
            "SELECT COUNT(*) AS count FROM vehicles WHERE status = 'published'"
        ).fetchone()["count"]

        featured_vehicles = db.execute(
            "SELECT COUNT(*) AS count FROM vehicles WHERE featured = 1"
        ).fetchone()["count"]
        total_visits = db.execute(
            "SELECT COUNT(*) AS count FROM site_visits"
        ).fetchone()["count"]

        today_visits = db.execute("""
            SELECT COUNT(*) AS count
            FROM site_visits
            WHERE (visited_at AT TIME ZONE 'America/Argentina/Cordoba')::date =
                  (CURRENT_TIMESTAMP AT TIME ZONE 'America/Argentina/Cordoba')::date
        """).fetchone()["count"]

        last_7_days_visits = db.execute("""
            SELECT COUNT(*) AS count
            FROM site_visits
            WHERE (visited_at AT TIME ZONE 'America/Argentina/Cordoba')::date >=
                  (CURRENT_TIMESTAMP AT TIME ZONE 'America/Argentina/Cordoba')::date - 6
        """).fetchone()["count"]

        visits_by_day = db.execute("""
            SELECT
                (visited_at AT TIME ZONE 'America/Argentina/Cordoba')::date AS day,
                COUNT(*) AS visits
            FROM site_visits
            WHERE (visited_at AT TIME ZONE 'America/Argentina/Cordoba')::date >=
                  (CURRENT_TIMESTAMP AT TIME ZONE 'America/Argentina/Cordoba')::date - 6
            GROUP BY day
            ORDER BY day DESC
        """).fetchall()

        users = db.execute("""
            SELECT id, name, email, phone, created_at
            FROM users
            ORDER BY id DESC
            LIMIT 100
        """).fetchall()

        vehicles = db.execute("""
            SELECT
                v.id, v.brand, v.model, v.year, v.price,
                v.location, v.status, v.featured, v.created_at,
                u.name AS owner_name,
                u.phone AS owner_phone,
                (
                    SELECT filename
                    FROM vehicle_photos p
                    WHERE p.vehicle_id = v.id
                    ORDER BY p.is_cover DESC, p.id
                    LIMIT 1
                ) AS photo
            FROM vehicles v
            LEFT JOIN users u ON u.id = v.user_id
            ORDER BY v.id DESC
            LIMIT 100
        """).fetchall()

    return render_template(
        "admin.html",
        total_users=total_users,
        total_vehicles=total_vehicles,
        published_vehicles=published_vehicles,
        featured_vehicles=featured_vehicles,
        total_visits=total_visits,
        today_visits=today_visits,
        last_7_days_visits=last_7_days_visits,
        visits_by_day=visits_by_day,
        users=users,
        vehicles=vehicles,
        csrf_token=session["admin_csrf_token"]
    )



@app.route("/admin/vehiculo/<int:vehicle_id>/editar", methods=["GET", "POST"])
@login_required
def admin_vehicle_edit(vehicle_id):
    user = current_user()
    if not user or user["role"] != "admin":
        abort(403)

    if request.method == "POST":
        verificar_admin()

        province = request.form.get("province", "").strip()
        neighborhood = request.form.get("neighborhood", "").strip()

        if province and province not in PROVINCES:
            flash("Selecciona una provincia valida.", "error")
            return redirect(url_for("admin_vehicle_edit", vehicle_id=vehicle_id))

        required = [
            "category", "brand", "model", "year", "price",
            "contact_name", "whatsapp"
        ]

        missing = [
            field for field in required
            if not request.form.get(field, "").strip()
        ]

        if missing:
            flash("CompletÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¡ todos los campos obligatorios.", "error")
            return redirect(url_for("admin_vehicle_edit", vehicle_id=vehicle_id))

        try:
            year = int(request.form["year"])
            price = float(request.form["price"])
            kilometers = int(request.form.get("kilometers") or 0)

            if year < 1900 or year > 2100 or price <= 0 or kilometers < 0:
                raise ValueError
        except ValueError:
            flash("RevisÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¡ el aÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â±o, el precio y los kilÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â³metros.", "error")
            return redirect(url_for("admin_vehicle_edit", vehicle_id=vehicle_id))

        accepts_trade = 1 if request.form.get("accepts_trade") == "on" else 0

        with get_db() as db:
            vehicle = db.execute(
                "SELECT province, location FROM vehicles WHERE id = %s",
                (vehicle_id,)
            ).fetchone()

            if not vehicle:
                abort(404)

            location = (
                f"{province}, {neighborhood}" if neighborhood
                else province
            ) if province else vehicle["location"]

            province_to_save = province or vehicle["province"]

            result = db.execute("""
                UPDATE vehicles SET
                    category = %s,
                    brand = %s,
                    model = %s,
                    year = %s,
                    kilometers = %s,
                    price = %s,
                    province = %s,
                    location = %s,
                    neighborhood = %s,
                    description = %s,
                    contact_name = %s,
                    whatsapp = %s,
                    email = %s,
                    accepts_trade = %s,
                    trade_details = %s
                WHERE id = %s
            """, (
                request.form["category"].strip(),
                request.form["brand"].strip(),
                request.form["model"].strip(),
                year,
                kilometers,
                price,
                province_to_save,
                location,
                neighborhood,
                request.form.get("description", "").strip(),
                request.form["contact_name"].strip(),
                request.form["whatsapp"].strip(),
                request.form.get("email", "").strip(),
                accepts_trade,
                request.form.get("trade_details", "").strip(),
                vehicle_id
            ))

            if result.rowcount == 0:
                abort(404)

        flash("VehÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â­culo actualizado correctamente.", "success")
        return redirect(url_for("admin_dashboard"))

    if not session.get("admin_csrf_token"):
        session["admin_csrf_token"] = secrets.token_urlsafe(32)

    with get_db() as db:
        vehicle = db.execute(
            "SELECT * FROM vehicles WHERE id = %s",
            (vehicle_id,)
        ).fetchone()

    if not vehicle:
        abort(404)

    return render_template(
        "admin_edit_vehicle.html",
        vehicle=vehicle,
        csrf_token=session["admin_csrf_token"],
        provinces=PROVINCES
    )


@app.route("/admin/vehiculo/<int:vehicle_id>/estado", methods=["POST"])
@login_required
def admin_vehicle_status(vehicle_id):
    verificar_admin()

    new_status = request.form.get("status")

    if new_status not in ("published", "suspended"):
        abort(400)

    with get_db() as db:
        result = db.execute(
            "UPDATE vehicles SET status = %s WHERE id = %s",
            (new_status, vehicle_id)
        )

        if result.rowcount == 0:
            abort(404)

    if new_status == "published":
        flash("La publicaciÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â³n fue reactivada.", "success")
    else:
        flash("La publicaciÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â³n fue suspendida.", "success")

    return redirect(url_for("admin_dashboard"))


@app.route("/admin/vehiculo/<int:vehicle_id>/eliminar", methods=["POST"])
@login_required
def admin_vehicle_delete(vehicle_id):
    verificar_admin()

    with get_db() as db:
        vehicle = db.execute(
            "SELECT id FROM vehicles WHERE id = %s",
            (vehicle_id,)
        ).fetchone()

        if not vehicle:
            abort(404)

        photos = db.execute(
            "SELECT filename FROM vehicle_photos WHERE vehicle_id = %s",
            (vehicle_id,)
        ).fetchall()

        filenames = [photo["filename"] for photo in photos]

        db.execute(
            "DELETE FROM vehicle_photos WHERE vehicle_id = %s",
            (vehicle_id,)
        )

        db.execute(
            "DELETE FROM vehicles WHERE id = %s",
            (vehicle_id,)
        )

    # Los archivos se eliminan solamente despues de borrar los registros.
    for filename in filenames:
        if not filename or Path(filename).name != filename:
            continue

        with get_db() as db:
            references = db.execute(
                "SELECT COUNT(*) AS count FROM vehicle_photos WHERE filename = %s",
                (filename,)
            ).fetchone()["count"]

        if references == 0:
            try:
                get_s3_client().delete_object(
                    Bucket=os.environ["SUPABASE_STORAGE_BUCKET"],
                    Key=filename
                )
            except Exception:
                app.logger.exception(
                    "No se pudo eliminar la foto %s de Supabase Storage",
                    filename
                )

    flash("El vehÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â­culo y sus fotografÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â­as fueron eliminados.", "success")
    return redirect(url_for("admin_dashboard"))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
