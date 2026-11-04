# Notas UCC: del código vulnerable a la mitigación

Proyecto final de Optativa sobre análisis, explotación controlada y mitigación de vulnerabilidades en software.

Integrantes: Doris Arzuaga, Jesús Egea, Diego Luna y Gabriela Zabaleta. Las responsabilidades de cada uno están en `PARTICIPACION.md`.

## Descripción

Notas UCC es una aplicación web pequeña para consultar calificaciones. Un estudiante inicia sesión y consulta sus propias notas. La construimos con Python 3, Flask 3 y SQLite, y le dejamos a propósito dos vulnerabilidades de naturaleza distinta para analizarlas, demostrarlas, corregirlas y comprobar la corrección.

Hay dos tipos de usuario. El estudiante autenticado puede iniciar sesión y ver solo sus notas. El visitante solo puede intentar iniciar sesión.

Las pruebas se hicieron únicamente en `127.0.0.1:8000` y `127.0.0.1:8001`, en nuestros propios equipos. Los usuarios, claves y notas son ficticios.

## Vulnerabilidades

1. Inyección SQL en `/login`. Es un error de implementación: la consulta se arma pegando el texto que escribe el usuario. Corresponde a A05:2025 Injection del OWASP Top 10 (A03 en la edición 2021). El riesgo pasó de crítico a medio después de la corrección.
2. BOLA en `/notas/<id>`. Es un error de diseño de la autorización: la ruta no revisa que la nota pertenezca a quien la pide. Corresponde a API1:2023 del OWASP API Security Top 10 y a A01:2025 Broken Access Control. El riesgo pasó de alto a bajo.

El detalle está en el informe ejecutivo (`informe/`), en `diagrama.md` y en `matrices.md`. El artículo de divulgación está en `PUBLICACION.md`.

## Contenido del repositorio

- `app_vulnerable/`: la aplicación con los dos fallos (puerto 8000).
- `app_corregida/`: la misma aplicación corregida y con controles adicionales (puerto 8001).
- `pruebas/pruebas.py`: prueba de concepto que ataca las dos versiones y compara los resultados.
- `pruebas/test_seguridad.py`: pruebas automatizadas con pytest.
- `evidencias/`: resultados de las pruebas, análisis estático, logs y diagrama.
- `.github/workflows/`: integración continua en GitHub Actions.
- `diagrama.md`: arquitectura, componentes y ubicación de cada fallo.
- `matrices.md`: matriz de riesgo, matriz de validación y riesgo residual.
- `informe/`: informe ejecutivo en PDF y Word.
- `PUBLICACION.md`: publicación técnica.
- `PARTICIPACION.md`: registro de participación.

## Instalación y ejecución

Se necesita Python 3.10 o superior.

```
pip install -r requirements.txt
```

En una terminal, la versión vulnerable:

```
cd app_vulnerable
python app.py
```

En otra terminal, la versión corregida:

```
cd app_corregida
python app.py
```

Con las dos corriendo, en una tercera terminal:

```
cd pruebas
python pruebas.py
```

El script muestra, para cada vulnerabilidad, que el ataque funciona en la versión vulnerable y se bloquea en la corregida. También comprueba que el uso normal sigue funcionando, revisa el manejo de errores, las cabeceras y el límite de intentos, y termina con un resumen de casos esperados y obtenidos.

Para las pruebas automatizadas y el análisis estático no hace falta levantar las apps:

```
pip install -r requirements-dev.txt
python -m pytest -v pruebas/
python -m bandit -r app_corregida -ll
python -m bandit -r app_vulnerable
python -m pip_audit -r requirements.txt
```

La clave de sesión de la versión corregida se puede definir con la variable de entorno `NOTAS_SECRET_KEY`. Si no se define, se genera una aleatoria en cada arranque.

Cada vez que se inicia una app se crea de nuevo `notas.db` con datos de prueba: `ana` con clave `ana2026` (notas 1 y 2) y `luis` con clave `luis2026` (nota 3).

## Resultados

En la versión vulnerable, la clave `' OR '1'='1` permite entrar como ana sin saber su clave, y el usuario `luis' --` permite entrar como luis. Además, luis puede leer la nota de ana cambiando el número en la dirección.

En la versión corregida, los dos ataques de inyección reciben 401, la lectura de la nota ajena recibe 403 y queda registrada en el log, y después de cinco intentos fallidos el login responde 429. El uso normal funciona igual en ambas versiones.

La prueba de concepto dio 16 de 16 casos correctos y las pruebas automatizadas 18 de 18. Bandit encontró dos problemas en la versión vulnerable (CWE-89 y CWE-259) y ninguno en la corregida.

## Referencias

- OWASP Foundation. (2025). OWASP Top 10:2025. https://owasp.org/Top10/
- OWASP Foundation. (2021). A03:2021 Injection. https://owasp.org/Top10/2021/A03_2021-Injection/
- OWASP Foundation. (2023). API1:2023 Broken Object Level Authorization. https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/
- OWASP Cheat Sheet Series. SQL Injection Prevention. https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
- OWASP Cheat Sheet Series. Authorization. https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html
- OWASP Cheat Sheet Series. Password Storage. https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
- OWASP Foundation. Application Security Verification Standard. https://owasp.org/www-project-application-security-verification-standard/
- MITRE. CWE-89 y CWE-639. https://cwe.mitre.org/
- Congreso de la República de Colombia. (2012). Ley Estatutaria 1581 de 2012. https://www.funcionpublica.gov.co/eva/gestornormativo/norma.php?i=49981
- Pallets. Flask Security Considerations. https://flask.palletsprojects.com/en/stable/web-security/
- PyCQA. Bandit. https://bandit.readthedocs.io/
