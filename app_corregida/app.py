import logging
import os
import re
import secrets
import sqlite3
import time

from flask import Flask, g, jsonify, request, session
from werkzeug.exceptions import HTTPException
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)

app.secret_key = os.environ.get("NOTAS_SECRET_KEY") or secrets.token_hex(32)

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("NOTAS_COOKIE_SECURE") == "1",
)

DB = "notas.db"

log_seguridad = logging.getLogger("seguridad")
if not log_seguridad.handlers:
    _h = logging.FileHandler("seguridad.log", encoding="utf-8")
    _h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    log_seguridad.addHandler(_h)
    log_seguridad.setLevel(logging.INFO)

MAX_FALLOS = 5
VENTANA_SEG = 60
_fallos = {}

PATRON_USUARIO = re.compile(r"[a-z0-9_]{1,30}")


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def cerrar_db(exc=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DB)
    db.executescript(
        """
        DROP TABLE IF EXISTS usuarios;
        DROP TABLE IF EXISTS notas;
        CREATE TABLE usuarios (id INTEGER PRIMARY KEY, usuario TEXT UNIQUE, clave_hash TEXT);
        CREATE TABLE notas (id INTEGER PRIMARY KEY, usuario_id INTEGER, materia TEXT, calificacion REAL);
        """
    )
    db.execute("INSERT INTO usuarios VALUES (1, 'ana', ?)", (generate_password_hash("ana2026"),))
    db.execute("INSERT INTO usuarios VALUES (2, 'luis', ?)", (generate_password_hash("luis2026"),))
    db.execute("INSERT INTO notas VALUES (1, 1, 'Ingeniería Web', 4.2)")
    db.execute("INSERT INTO notas VALUES (2, 1, 'Optativa', 4.8)")
    db.execute("INSERT INTO notas VALUES (3, 2, 'Ingeniería Web', 3.9)")
    db.commit()
    db.close()


def _bloqueado(ip):
    ahora = time.time()
    recientes = [t for t in _fallos.get(ip, []) if ahora - t < VENTANA_SEG]
    _fallos[ip] = recientes
    return len(recientes) >= MAX_FALLOS


def _registrar_fallo(ip, usuario):
    _fallos.setdefault(ip, []).append(time.time())
    log_seguridad.warning("login_fallido ip=%s usuario=%r", ip, usuario[:30])


@app.post("/login")
def login():
    ip = request.remote_addr or "desconocida"
    if _bloqueado(ip):
        log_seguridad.warning("login_bloqueado_rate_limit ip=%s", ip)
        return jsonify({"ok": False, "error": "Demasiados intentos. Espere un momento."}), 429

    usuario = request.form.get("usuario", "")
    clave = request.form.get("clave", "")

    if not PATRON_USUARIO.fullmatch(usuario) or not (1 <= len(clave) <= 128):
        _registrar_fallo(ip, usuario)
        return jsonify({"ok": False, "error": "Credenciales inválidas"}), 401

    db = get_db()
    # Corrección V1: consulta parametrizada y clave con hash
    fila = db.execute(
        "SELECT id, usuario, clave_hash FROM usuarios WHERE usuario = ?", (usuario,)
    ).fetchone()
    if fila and check_password_hash(fila["clave_hash"], clave):
        session.clear()
        session["usuario_id"] = fila["id"]
        _fallos.pop(ip, None)
        log_seguridad.info("login_ok usuario_id=%s", fila["id"])
        return jsonify({"ok": True, "usuario_id": fila["id"], "usuario": fila["usuario"]})

    _registrar_fallo(ip, usuario)
    return jsonify({"ok": False, "error": "Credenciales inválidas"}), 401


@app.get("/notas/<int:nota_id>")
def ver_nota(nota_id):
    if "usuario_id" not in session:
        return jsonify({"ok": False, "error": "No autenticado"}), 401
    db = get_db()
    nota = db.execute("SELECT * FROM notas WHERE id = ?", (nota_id,)).fetchone()
    if not nota:
        return jsonify({"ok": False, "error": "No existe"}), 404
    # Corrección V2: solo el dueño puede ver la nota
    if nota["usuario_id"] != session["usuario_id"]:
        log_seguridad.warning(
            "acceso_denegado usuario_id=%s nota_id=%s dueno=%s",
            session["usuario_id"], nota_id, nota["usuario_id"],
        )
        return jsonify({"ok": False, "error": "No autorizado"}), 403
    return jsonify({"ok": True, "nota": dict(nota)})


@app.post("/logout")
def logout():
    session.clear()
    return jsonify({"ok": True})


@app.get("/salud")
def salud():
    return jsonify({"ok": True, "version": "corregida"})


@app.after_request
def cabeceras_seguridad(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.errorhandler(404)
def no_encontrado(_e):
    return jsonify({"ok": False, "error": "No existe"}), 404


@app.errorhandler(405)
def metodo_no_permitido(_e):
    return jsonify({"ok": False, "error": "Método no permitido"}), 405


@app.errorhandler(Exception)
def error_interno(e):
    if isinstance(e, HTTPException):
        return jsonify({"ok": False, "error": "Solicitud no válida"}), e.code
    log_seguridad.error("error_interno tipo=%s", type(e).__name__)
    return jsonify({"ok": False, "error": "Error interno"}), 500


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=8001, debug=False)
