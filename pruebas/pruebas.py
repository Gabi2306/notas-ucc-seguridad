import sys

import requests

try:
    sys.stdout.reconfigure(encoding="utf-8")
except AttributeError:
    pass

VULN = "http://127.0.0.1:8000"
FIX = "http://127.0.0.1:8001"
resumen = []


def linea(t):
    print("\n=== " + t)


def registrar(caso, version, esperado, obtenido):
    ok = esperado == obtenido
    resumen.append((caso, version, esperado, obtenido, "OK" if ok else "FALLA"))


def post_login(base, usuario, clave, sesion=None):
    cliente = sesion or requests
    r = cliente.post(f"{base}/login", data={"usuario": usuario, "clave": clave})
    print(f"POST /login usuario={usuario!r} clave={clave!r}  ->", r.status_code, r.json())
    return r


def get_nota(base, sesion, nota_id, desc):
    r = sesion.get(f"{base}/notas/{nota_id}")
    print(f"GET /notas/{nota_id} ({desc}) ->", r.status_code, r.json())
    return r


def sesion_legitima(base, usuario, clave):
    s = requests.Session()
    post_login(base, usuario, clave, s)
    return s


if __name__ == "__main__":
    for base, nombre, esperado in ((VULN, "VULNERABLE", 200), (FIX, "CORREGIDA", 401)):
        linea(f"V1-a SQLi en la clave (' OR '1'='1) contra la app {nombre}")
        r = post_login(base, "ana", "' OR '1'='1")
        print("Resultado:", "login SIN clave real -> ataque LOGRADO" if r.status_code == 200 else "ataque bloqueado")
        registrar("V1-a SQLi ' OR '1'='1", nombre, esperado, r.status_code)

        linea(f"V1-b SQLi dirigida a una cuenta concreta (luis' --) contra la app {nombre}")
        r = post_login(base, "luis' --", "cualquiera")
        if r.status_code == 200:
            print("Resultado: sesión abierta como", r.json().get("usuario"), "-> suplantación LOGRADA")
        else:
            print("Resultado: ataque bloqueado")
        registrar("V1-b SQLi luis' --", nombre, esperado, r.status_code)

    sesiones = {}
    for base, nombre, esperado in ((VULN, "VULNERABLE", 200), (FIX, "CORREGIDA", 403)):
        linea(f"V2 BOLA: luis autenticado pide la nota 2 (de ana) en la app {nombre}")
        s = sesion_legitima(base, "luis", "luis2026")
        sesiones[nombre] = s
        r = get_nota(base, s, 2, "sesión de luis, la nota es de ana")
        print("Resultado:", "lectura de nota ajena LOGRADA" if r.status_code == 200 else "acceso denegado")
        registrar("V2 BOLA nota ajena", nombre, esperado, r.status_code)

    for base, nombre in ((VULN, "VULNERABLE"), (FIX, "CORREGIDA")):
        linea(f"Legítimo: luis lee su propia nota (3) en la app {nombre}")
        r = get_nota(base, sesiones[nombre], 3, "recurso propio")
        registrar("Legítimo: nota propia", nombre, 200, r.status_code)

        linea(f"Legítimo: ana inicia sesión con su clave real en la app {nombre}")
        r = post_login(base, "ana", "ana2026")
        registrar("Legítimo: login con clave real", nombre, 200, r.status_code)

        linea(f"Error seguro: petición sin sesión y nota inexistente en la app {nombre}")
        r = requests.get(f"{base}/notas/1")
        print("GET /notas/1 (sin sesión) ->", r.status_code, r.json())
        registrar("Sin sesión", nombre, 401, r.status_code)
        r = get_nota(base, sesiones[nombre], 999, "no existe")
        registrar("Nota inexistente", nombre, 404, r.status_code)

    linea("Defensa en profundidad: cabeceras de seguridad en la app CORREGIDA")
    r = requests.get(f"{FIX}/salud")
    for h in ("X-Content-Type-Options", "X-Frame-Options", "Content-Security-Policy", "Cache-Control"):
        print(f"  {h}: {r.headers.get(h)}")
    registrar("Cabeceras de seguridad", "CORREGIDA", True, all(
        r.headers.get(h) for h in ("X-Content-Type-Options", "X-Frame-Options", "Content-Security-Policy")))

    linea("Defensa en profundidad: rate limiting de /login en la app CORREGIDA")
    codigos = []
    for i in range(7):
        rr = requests.post(f"{FIX}/login", data={"usuario": "ana", "clave": f"mala{i}"})
        codigos.append(rr.status_code)
    print("7 intentos fallidos seguidos ->", codigos)
    registrar("Rate limiting (7.º intento)", "CORREGIDA", 429, codigos[-1])
    rr = requests.post(f"{VULN}/login", data={"usuario": "ana", "clave": "mala"})
    print("Mismo intento en la app VULNERABLE (sin límite) ->", rr.status_code)

    linea("RESUMEN (esperado vs. obtenido)")
    print(f"{'Caso':32} {'Versión':11} {'Esperado':9} {'Obtenido':9} Estado")
    for caso, version, esp, obt, estado in resumen:
        print(f"{caso:32} {version:11} {str(esp):9} {str(obt):9} {estado}")
    fallas = sum(1 for x in resumen if x[4] != "OK")
    print(f"\n{len(resumen) - fallas}/{len(resumen)} casos con el resultado esperado.")
    sys.exit(1 if fallas else 0)
