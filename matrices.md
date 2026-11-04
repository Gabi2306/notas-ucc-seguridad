# Matrices de riesgo y validación

## Escala

El riesgo se calcula como probabilidad por impacto, cada uno de 1 (bajo) a 3 (alto). Un puntaje de 1 o 2 es bajo, de 3 o 4 es medio, de 6 es alto y de 9 es crítico.

## Matriz de riesgo antes de corregir

| Vulnerabilidad | Probabilidad | Impacto | Nivel de riesgo | Justificación |
|---|---|---|---|---|
| Inyección SQL en `/login` | 3, alta. La entrada llega sin filtro, el ataque no necesita cuenta ni herramientas especiales y los payloads son públicos | 3, alto. Permite suplantar cualquier cuenta, lo que compromete la autenticidad y, con ella, la confidencialidad e integridad de lo que esa cuenta puede ver o hacer | Crítico (9) | Rompe la entrada al sistema y la puede explotar un visitante anónimo |
| BOLA en `/notas/<id>` | 3, alta. Basta una cuenta cualquiera y cambiar un número consecutivo en la dirección | 2, medio alto. Expone calificaciones ajenas (confidencialidad). No permite modificarlas, pero son datos personales protegidos por la Ley 1581 de 2012 | Alto (6) | No depende de la inyección. Es un fallo de diseño que se repetiría en cada ruta nueva si no se corrige |

## Matriz de validación

Resultados de `pruebas/pruebas.py` y `pruebas/test_seguridad.py`, guardados en `evidencias/resultado_pruebas.txt` y `evidencias/resultado_pytest.txt`.

| Caso de prueba | Resultado vulnerable | Control aplicado | Resultado corregido |
|---|---|---|---|
| Inyección con `usuario=ana` y `clave=' OR '1'='1` | 200, sesión como ana sin su clave | Consulta parametrizada y clave comparada con hash | 401, credenciales inválidas |
| Inyección dirigida con `usuario=luis' --` | 200, sesión como luis | Lista blanca para el usuario y consulta parametrizada | 401, mismo mensaje genérico |
| BOLA: luis pide `GET /notas/2`, que es de ana | 200, devuelve la nota ajena | Comparación del dueño de la nota con el usuario de la sesión | 403, no autorizado, y queda en `seguridad.log` |
| Uso legítimo: luis pide su nota 3 | 200 | Sin cambios | 200 |
| Uso legítimo: ana entra con `ana2026` | 200 | Sin cambios | 200 |
| Errores: sin sesión, nota inexistente y ruta inexistente | 401, 404 y página HTML de Werkzeug | Respuestas de error genéricas en JSON | 401, 404 y 404 en JSON, sin detalles internos |
| Fuerza bruta: 7 claves erróneas seguidas | 401 sin límite | Límite de 5 fallos en 60 segundos | 401 cinco veces y luego 429 |
| Cabeceras y cookie | Sin cabeceras de seguridad | `nosniff`, `X-Frame-Options`, CSP, `no-store`, cookie `HttpOnly` y `SameSite=Lax` | Presentes |
| Análisis estático con bandit | B608 (CWE-89) y B105 (CWE-259) | Correcciones de la inyección y clave de sesión fuera del código | Sin hallazgos |

La prueba de concepto dio 16 de 16 casos correctos y las pruebas automatizadas 18 de 18.

## Matriz de riesgo residual

| Vulnerabilidad | Probabilidad | Impacto | Riesgo inicial | Riesgo residual | Lo que queda abierto |
|---|---|---|---|---|---|
| Inyección SQL | 1, baja. La entrada ya no puede alterar el SQL | 3, alto, si apareciera otra consulta armada con texto | Crítico (9) | Medio (3) | Claves débiles, sin segundo factor. El límite de intentos está en memoria y por IP, así que se reinicia con la app |
| BOLA | 1, baja. El dueño se revisa en cada petición | 2, medio alto | Alto (6) | Bajo (2) | La regla está en cada ruta y una ruta nueva podría olvidarla. Los ids son consecutivos y el 403 confirma que la nota existe |
