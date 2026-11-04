import importlib.util
import logging
import os
import pathlib

import pytest

RAIZ = pathlib.Path(__file__).resolve().parent.parent


def _cargar(carpeta, nombre, tmp_path):
    os.chdir(tmp_path)
    for h in list(logging.getLogger("seguridad").handlers):
        h.close()
        logging.getLogger("seguridad").removeHandler(h)
    spec = importlib.util.spec_from_file_location(nombre, RAIZ / carpeta / "app.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.DB = str(tmp_path / f"{nombre}.db")
    mod.init_db()
    mod.app.config["TESTING"] = True
    return mod


@pytest.fixture
def vulnerable(tmp_path):
    return _cargar("app_vulnerable", "app_vulnerable", tmp_path).app.test_client()


@pytest.fixture
def corregida_mod(tmp_path):
    return _cargar("app_corregida", "app_corregida", tmp_path)


@pytest.fixture
def corregida(corregida_mod):
    corregida_mod._fallos.clear()
    return corregida_mod.app.test_client()


def login(cliente, usuario, clave):
    return cliente.post("/login", data={"usuario": usuario, "clave": clave})


SQLI = [("ana", "' OR '1'='1"), ("luis' --", "x"), ("' OR 1=1 --", "x")]


@pytest.mark.parametrize("usuario,clave", SQLI)
def test_v1_sqli_funciona_en_vulnerable(vulnerable, usuario, clave):
    assert login(vulnerable, usuario, clave).status_code == 200


def test_v1_sqli_suplanta_cuenta_concreta_en_vulnerable(vulnerable):
    r = login(vulnerable, "luis' --", "x")
    assert r.get_json()["usuario"] == "luis"


@pytest.mark.parametrize("usuario,clave", SQLI)
def test_v1_sqli_bloqueada_en_corregida(corregida, usuario, clave):
    r = login(corregida, usuario, clave)
    assert r.status_code == 401
    assert r.get_json() == {"ok": False, "error": "Credenciales inválidas"}


def test_v1_claves_guardadas_con_hash(corregida_mod):
    import sqlite3
    db = sqlite3.connect(corregida_mod.DB)
    claves = [f[0] for f in db.execute("SELECT clave_hash FROM usuarios")]
    assert all(c not in ("ana2026", "luis2026") and ":" in c for c in claves)


def test_v2_bola_funciona_en_vulnerable(vulnerable):
    login(vulnerable, "luis", "luis2026")
    r = vulnerable.get("/notas/2")
    assert r.status_code == 200 and r.get_json()["nota"]["usuario_id"] == 1


def test_v2_bola_bloqueada_en_corregida(corregida):
    login(corregida, "luis", "luis2026")
    r = corregida.get("/notas/2")
    assert r.status_code == 403
    assert "nota" not in r.get_json()


@pytest.mark.parametrize("app_fixture", ["vulnerable", "corregida"])
def test_legitimo_login_y_nota_propia(request, app_fixture):
    c = request.getfixturevalue(app_fixture)
    assert login(c, "ana", "ana2026").status_code == 200
    assert c.get("/notas/1").status_code == 200
    assert c.get("/notas/2").status_code == 200


@pytest.mark.parametrize("app_fixture", ["vulnerable", "corregida"])
def test_legitimo_clave_incorrecta_rechazada(request, app_fixture):
    c = request.getfixturevalue(app_fixture)
    assert login(c, "ana", "mala").status_code == 401


def test_errores_genericos_en_corregida(corregida):
    assert corregida.get("/notas/1").status_code == 401
    login(corregida, "luis", "luis2026")
    r = corregida.get("/notas/999")
    assert r.status_code == 404 and r.get_json()["error"] == "No existe"
    r = corregida.get("/ruta-que-no-existe")
    assert r.status_code == 404 and r.is_json


def test_rate_limiting_login(corregida):
    codigos = [login(corregida, "ana", f"mala{i}").status_code for i in range(6)]
    assert codigos[:5] == [401] * 5 and codigos[5] == 429
    assert login(corregida, "ana", "ana2026").status_code == 429


def test_cabeceras_y_cookie_seguras(corregida):
    r = login(corregida, "ana", "ana2026")
    cookie = r.headers.get("Set-Cookie", "")
    assert "HttpOnly" in cookie and "SameSite=Lax" in cookie
    for h in ("X-Content-Type-Options", "X-Frame-Options", "Content-Security-Policy"):
        assert h in r.headers


def test_accesos_denegados_quedan_registrados(corregida, tmp_path):
    login(corregida, "luis", "luis2026")
    corregida.get("/notas/2")
    texto = (tmp_path / "seguridad.log").read_text(encoding="utf-8")
    assert "acceso_denegado usuario_id=2 nota_id=2" in texto
    assert "luis2026" not in texto
