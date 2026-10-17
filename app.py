import csv
import io
import os
import secrets
import unicodedata
from datetime import datetime, timezone
from functools import wraps

import pandas as pd
from flask import Flask, abort, flash, jsonify, redirect, render_template, request, Response, url_for
from flask_login import LoginManager, UserMixin, current_user, login_required, login_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import check_password_hash, generate_password_hash
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY") or secrets.token_urlsafe(48)
app.config["MAX_CONTENT_LENGTH"] = 15 * 1024 * 1024
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("COOKIE_SECURE", "true").lower() == "true"
app.config["REMEMBER_COOKIE_HTTPONLY"] = True
app.config["REMEMBER_COOKIE_SECURE"] = app.config["SESSION_COOKIE_SECURE"]
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

database_url = os.environ.get("DATABASE_URL", "")
if database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)
if database_url:
    app.config["SQLALCHEMY_DATABASE_URI"] = database_url
else:
    # Solo para pruebas locales. En producción configurá DATABASE_URL con PostgreSQL.
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///legajos_local.db"

db = SQLAlchemy(app)
csrf = CSRFProtect(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message = "Iniciá sesión para acceder a los legajos."
login_manager.login_message_category = "warning"

ALIASES = {
    "legajo": ["legajo","nro legajo","numero legajo","numero de legajo","n de legajo","n° de legajo","nº de legajo","id empleado","employee id","ficha","numero de ficha"],
    "nombre": ["nombre","nombres","first name","nombre de pila"],
    "apellido": ["apellido","apellidos","last name","surname"],
    "nombreCompleto": ["nombre completo","nombre y apellido","apellido y nombre","nombre empleado","nombre del empleado","empleado","trabajador","full name","employee name"],
    "dni": ["dni","documento","numero de documento","nro dni"],
    "cuil": ["cuil","cuit","cuil cuit"],
    "email": ["email","e mail","mail","correo","correo electronico","email laboral"],
    "telefono": ["telefono","tel","celular","movil","phone","telefono laboral"],
    "sector": ["area","sector","departamento","gerencia","division","unidad organizativa"],
    "puesto": ["puesto","cargo","funcion","puesto de trabajo","posicion","job title"],
    "ingreso": ["fecha de ingreso","fecha ingreso","ingreso","fecha de alta","fecha alta","hire date"],
    "nacimiento": ["fecha de nacimiento","fecha nacimiento","nacimiento","birth date"],
    "estado": ["estado","situacion","estado laboral","situacion laboral","activo"],
    "sede": ["sucursal","sede","establecimiento","planta","localidad laboral"],
    "domicilio": ["domicilio","direccion","direccion particular","domicilio particular"],
    "responsable": ["jefe","supervisor","responsable","jefe directo","reporta a"]
}
LABELS = {
    "legajo":"N.º de legajo","nombre":"Nombre","apellido":"Apellido","nombreCompleto":"Nombre completo",
    "dni":"DNI / documento","cuil":"CUIL / CUIT","email":"Correo electrónico","telefono":"Teléfono",
    "sector":"Área / sector","puesto":"Puesto / cargo","ingreso":"Fecha de ingreso",
    "nacimiento":"Fecha de nacimiento","estado":"Estado laboral","sede":"Sede / sucursal",
    "domicilio":"Domicilio","responsable":"Jefe / responsable"
}

def norm(value):
    value = unicodedata.normalize("NFD", str(value or ""))
    value = "".join(c for c in value if unicodedata.category(c) != "Mn")
    return "".join(c.lower() for c in value if c.isalnum())

def clean(value):
    if value is None:
        return ""
    if hasattr(value, "strftime"):
        return value.strftime("%d/%m/%Y")
    return str(value).strip()

def canonical_header(header):
    n = norm(header)
    for key, aliases in ALIASES.items():
        if n in {norm(a) for a in aliases}:
            return key
    return ""

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="viewer")
    active = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Employee(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    legajo = db.Column(db.String(120), unique=True, nullable=False, index=True)
    data = db.Column(db.JSON, nullable=False, default=dict)
    extras = db.Column(db.JSON, nullable=False, default=dict)
    sources = db.Column(db.JSON, nullable=False, default=list)
    updated_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    action = db.Column(db.String(120), nullable=False)
    detail = db.Column(db.String(500), nullable=False, default="")
    created_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))

def log_action(action, detail=""):
    db.session.add(AuditLog(username=current_user.username if current_user.is_authenticated else "system",
                            action=action, detail=detail[:500]))

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

@login_manager.unauthorized_handler
def unauthorized():
    return redirect(url_for("login", next=request.path))

def admin_required(fn):
    @wraps(fn)
    @login_required
    def wrapper(*args, **kwargs):
        if current_user.role != "admin":
            abort(403)
        return fn(*args, **kwargs)
    return wrapper

@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Cache-Control"] = "no-store"
    return response

@app.cli.command("init-db")
def init_db():
    """Create tables and optionally create the first administrator from environment variables."""
    db.create_all()
    username = os.environ.get("ADMIN_USERNAME", "").strip()
    password = os.environ.get("ADMIN_PASSWORD", "")
    if username and password:
        user = db.session.scalar(select(User).where(User.username == username))
        if user is None:
            user = User(username=username, role="admin")
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            print(f"Administrador creado: {username}")
        else:
            print("El usuario administrador ya existe; no se modificó.")
    print("Base de datos inicializada.")

@app.cli.command("create-user")
def create_user():
    """Interactive user creation: flask --app app create-user"""
    username = input("Usuario: ").strip()
    password = input("Contraseña (mínimo 14 caracteres): ")
    role = input("Rol (admin/viewer) [viewer]: ").strip().lower() or "viewer"
    if len(password) < 14:
        print("La contraseña debe tener al menos 14 caracteres.")
        return
    if role not in ("admin", "viewer"):
        print("Rol inválido.")
        return
    if db.session.scalar(select(User).where(User.username == username)):
        print("Ese usuario ya existe.")
        return
    user = User(username=username, role=role)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    print("Usuario creado.")

@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("index"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = db.session.scalar(select(User).where(User.username == username, User.active.is_(True)))
        if user and user.check_password(password):
            login_user(user)
            log_action("login")
            db.session.commit()
            next_url = request.args.get("next", "")
            if next_url.startswith("/") and not next_url.startswith("//"):
                return redirect(next_url)
            return redirect(url_for("index"))
        flash("Usuario o contraseña incorrectos.", "error")
    return render_template("login.html")

@app.post("/logout")
@login_required
def logout():
    log_action("logout")
    db.session.commit()
    logout_user()
    return redirect(url_for("login"))

@app.route("/")
@login_required
def index():
    return render_template("index.html", user=current_user, csrf_token_value=csrf._get_csrf_token())

@app.get("/api/employees")
@login_required
def api_employees():
    q = norm(request.args.get("q", ""))
    employees = db.session.scalars(select(Employee).order_by(Employee.legajo)).all()
    output = []
    for e in employees:
        searchable = norm(" ".join([e.legajo] + list(e.data.values()) + list(e.extras.values())))
        if q and q not in searchable:
            continue
        output.append(employee_payload(e))
    log_action("search", f"q={request.args.get('q','')[:100]}")
    db.session.commit()
    return jsonify({"employees": output, "total": len(output)})

def employee_payload(e):
    data = dict(e.data or {})
    return {"legajo": e.legajo, "data": data, "extras": e.extras or {}, "sources": e.sources or [],
            "name": data.get("nombreCompleto") or " ".join(x for x in [data.get("nombre",""), data.get("apellido","")] if x).strip() or "Nombre no informado",
            "updated_at": e.updated_at.isoformat() if e.updated_at else ""}

@app.get("/api/employees/<path:legajo>")
@login_required
def api_employee(legajo):
    e = db.session.scalar(select(Employee).where(Employee.legajo == legajo))
    if not e:
        abort(404)
    log_action("view_profile", f"legajo={legajo}")
    db.session.commit()
    return jsonify(employee_payload(e))

@app.post("/api/import")
@admin_required
def api_import():
    uploads = request.files.getlist("files")
    if not uploads:
        return jsonify({"error": "Seleccioná al menos un archivo."}), 400
    created = updated = skipped = processed = 0
    for upload in uploads:
        filename = upload.filename or "archivo"
        lower = filename.lower()
        if not (lower.endswith(".xlsx") or lower.endswith(".xls") or lower.endswith(".csv")):
            skipped += 1
            continue
        try:
            if lower.endswith(".csv"):
                raw = upload.read()
                try:
                    frame = pd.read_csv(io.BytesIO(raw), dtype=str, keep_default_na=False, sep=None, engine="python", encoding="utf-8-sig")
                except UnicodeDecodeError:
                    frame = pd.read_csv(io.BytesIO(raw), dtype=str, keep_default_na=False, sep=None, engine="python", encoding="latin-1")
            else:
                frame = pd.read_excel(upload, dtype=str, keep_default_na=False)
        except Exception:
            skipped += 1
            continue
        headers = {col: canonical_header(col) for col in frame.columns}
        legajo_col = next((col for col, canonical in headers.items() if canonical == "legajo"), None)
        if legajo_col is None:
            skipped += 1
            continue
        count = 0
        for _, row in frame.iterrows():
            legajo = clean(row.get(legajo_col, ""))
            if not legajo:
                skipped += 1
                continue
            mapped, extras = {}, {}
            for col in frame.columns:
                value = clean(row[col])
                if not value:
                    continue
                canonical = headers[col]
                if canonical:
                    mapped[canonical] = value
                else:
                    extras[str(col)] = value
            emp = db.session.scalar(select(Employee).where(Employee.legajo == legajo))
            if emp is None:
                emp = Employee(legajo=legajo, data={}, extras={}, sources=[])
                db.session.add(emp)
                created += 1
            else:
                updated += 1
            data = dict(emp.data or {})
            data.update(mapped)
            extra_data = dict(emp.extras or {})
            extra_data.update(extras)
            sources = list(emp.sources or [])
            if filename not in sources:
                sources.append(filename)
            emp.data, emp.extras, emp.sources = data, extra_data, sources
            count += 1
        if count:
            processed += 1
    try:
        log_action("import", f"archivos procesados={processed}; nuevos={created}; combinados={updated}; omitidos={skipped}")
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return jsonify({"error": "Hubo un conflicto al guardar. No se confirmó la importación; revisá los legajos duplicados e intentá nuevamente."}), 409
    return jsonify({"message": "Importación finalizada.", "files_processed": processed, "created": created, "updated": updated, "skipped": skipped})

@app.get("/api/export.csv")
@admin_required
def export_csv():
    employees = db.session.scalars(select(Employee).order_by(Employee.legajo)).all()
    keys = set(["legajo"])
    for e in employees:
        keys.update((e.data or {}).keys())
        keys.update((e.extras or {}).keys())
    ordered = ["legajo"] + sorted(k for k in keys if k != "legajo")
    output = io.StringIO()
    writer = csv.writer(output, delimiter=";")
    writer.writerow([LABELS.get(k, k) for k in ordered])
    for e in employees:
        row = {"legajo": e.legajo, **(e.data or {}), **(e.extras or {})}
        writer.writerow([row.get(k, "") for k in ordered])
    log_action("export_csv", f"cantidad={len(employees)}")
    db.session.commit()
    return Response("\ufeff" + output.getvalue(), mimetype="text/csv; charset=utf-8",
                    headers={"Content-Disposition": "attachment; filename=legajos_exportados.csv"})

@app.errorhandler(403)
def forbidden(_):
    return render_template("error.html", code=403, message="Tu usuario no tiene permiso para realizar esta acción."), 403

@app.errorhandler(404)
def not_found(_):
    if request.path.startswith("/api/"):
        return jsonify({"error":"No se encontró el legajo solicitado."}), 404
    return render_template("error.html", code=404, message="No encontramos esa página."), 404

@app.errorhandler(413)
def too_large(_):
    if request.path.startswith("/api/"):
        return jsonify({"error":"Los archivos superan el límite de 15 MB."}), 413
    return render_template("error.html", code=413, message="El archivo supera el límite de 15 MB."), 413

with app.app_context():
    db.create_all()
