import sqlite3

from flask import Flask, g, jsonify, request, session

app = Flask(__name__)
app.secret_key = "clave-de-laboratorio-no-usar-en-produccion"
DB = "notas.db"


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
        CREATE TABLE usuarios (id INTEGER PRIMARY KEY, usuario TEXT UNIQUE, clave TEXT);
        CREATE TABLE notas (id INTEGER PRIMARY KEY, usuario_id INTEGER, materia TEXT, calificacion REAL);
        """
    )
    db.execute("INSERT INTO usuarios VALUES (1, 'ana', 'ana2026')")
    db.execute("INSERT INTO usuarios VALUES (2, 'luis', 'luis2026')")
    db.execute("INSERT INTO notas VALUES (1, 1, 'Ingeniería Web', 4.2)")
    db.execute("INSERT INTO notas VALUES (2, 1, 'Optativa', 4.8)")
    db.execute("INSERT INTO notas VALUES (3, 2, 'Ingeniería Web', 3.9)")
    db.commit()
    db.close()


@app.post("/login")
def login():
    usuario = request.form.get("usuario", "")
    clave = request.form.get("clave", "")
    db = get_db()
    # Vulnerable: la entrada se concatena en el SQL
    consulta = f"SELECT id, usuario FROM usuarios WHERE usuario = '{usuario}' AND clave = '{clave}'"
    fila = db.execute(consulta).fetchone()
    if fila:
        session["usuario_id"] = fila["id"]
        return jsonify({"ok": True, "usuario_id": fila["id"], "usuario": fila["usuario"]})
    return jsonify({"ok": False, "error": "Credenciales inválidas"}), 401


@app.get("/notas/<int:nota_id>")
def ver_nota(nota_id):
    if "usuario_id" not in session:
        return jsonify({"ok": False, "error": "No autenticado"}), 401
    db = get_db()
    nota = db.execute("SELECT * FROM notas WHERE id = ?", (nota_id,)).fetchone()
    if not nota:
        return jsonify({"ok": False, "error": "No existe"}), 404
    # Vulnerable: no se verifica que la nota sea del usuario de la sesión
    return jsonify({"ok": True, "nota": dict(nota)})


@app.get("/salud")
def salud():
    return jsonify({"ok": True, "version": "vulnerable"})


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=8000, debug=False)
