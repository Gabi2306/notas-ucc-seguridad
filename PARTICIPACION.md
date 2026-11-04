# Registro de participación

## Gabriela Zabaleta

Rol: coordinación, arquitectura y aplicación base.

Responsabilidades: selección y diseño de la aplicación, construcción de la versión vulnerable con las rutas `/login` y `/notas/<id>`, diagrama de arquitectura y flujo de datos, alcance autorizado, instrucciones de instalación y consolidación del informe ejecutivo.

Archivos: `app_vulnerable/app.py`, `README.md`, `requirements.txt`, `requirements-dev.txt`, `.gitignore`, `diagrama.md`, `evidencias/diagrama_flujo.png` e `informe/` (secciones 1 y 7, y consolidación).

Commits:

- https://github.com/Gabi2306/notas-ucc-seguridad/commit/b763622347d7ad42ec6b596b0ce1ba8bb2136075
- https://github.com/Gabi2306/notas-ucc-seguridad/commit/19a0cfdc29ebabdb7cc4272742cc57f114c3439b

## Doris Arzuaga

Rol: análisis y mitigación.

Responsabilidades: caracterización de la inyección SQL y del BOLA, relación con OWASP, implementación de las correcciones (consulta parametrizada, hash de claves y verificación del dueño de la nota) y de los controles adicionales (lista blanca, límite de intentos, logs, cabeceras y errores genéricos).

Archivos: `app_corregida/app.py` e informe (secciones 2.1 y 4).

Commits:

- https://github.com/Gabi2306/notas-ucc-seguridad/commit/6d64eebadaaa99d089cbf411366aa9a7acb792b5

## Jesús Egea

Rol: explotación controlada e integración continua.

Responsabilidades: pruebas de concepto de la inyección SQL (`' OR '1'='1` y `luis' --`) y del BOLA con dos sesiones, ejecución antes y después, generación de evidencias y configuración de la integración continua con pytest, bandit y pip-audit.

Archivos: `pruebas/pruebas.py`, `.github/workflows/seguridad.yml`, resultados y logs de `evidencias/` e informe (secciones 2.2 y 5). En su commit también subió `pruebas/test_seguridad.py`, que preparó Diego.

Commits:

- https://github.com/Gabi2306/notas-ucc-seguridad/commit/a43776fe61ab6b3f35a6b4a0796c80800db47dc5

## Diego Luna

Rol: validación automatizada, riesgo y ética.

Responsabilidades: pruebas automatizadas de ataques, uso legítimo y controles adicionales, matriz de riesgo inicial y residual, reflexión ética, propuesta de seguridad en el ciclo de vida y el despliegue, y publicación técnica.

Archivos: `pruebas/test_seguridad.py` (subido al repositorio en el commit de Jesús), `matrices.md`, `PUBLICACION.md`, `PARTICIPACION.md` e informe (secciones 3 y 6).

Commits:

- https://github.com/Gabi2306/notas-ucc-seguridad/commit/53f972aa59f065e6f73d6b9202f1e1652c214de1

## Cronograma

- Semana 9: selección de la aplicación y construcción de la versión vulnerable (Gabriela).
- Semana 10: identificación de las dos vulnerabilidades, relación con OWASP y primera prueba de concepto (Doris y Jesús).
- Semana 11: revisión intermedia con diagrama preliminar, prueba de concepto de la inyección SQL y propuesta de mitigación (todo el equipo).
- Semana 12: correcciones, controles adicionales y pruebas automatizadas (Doris y Diego).
- Semana 13: integración continua, evidencias, matrices de riesgo, reflexión ética e informe (Jesús, Diego y Gabriela).
- Semana 14: publicación técnica y ensayo de la sustentación (todo el equipo).

## Decisiones del equipo

- Construimos una aplicación propia en lugar de usar un laboratorio externo, porque el proyecto exige intervenir el código y una aplicación pequeña permite aislar cada vulnerabilidad.
- Elegimos inyección SQL y BOLA porque son de naturaleza distinta (una de implementación y otra de diseño de la autorización) y no dependen una de la otra.
- Respondemos 403 y no 404 cuando se pide una nota ajena, porque hace más claro el control en la demostración. La posibilidad de enumerar ids quedó documentada como riesgo residual.
- Agregamos controles adicionales (límite de intentos, logs y cabeceras) para que un fallo en un solo control no deje expuesto el sistema.

## Historial completo

https://github.com/Gabi2306/notas-ucc-seguridad/commits/main

## Dominio del proyecto

Todos los integrantes revisamos el proyecto completo y podemos explicar las dos vulnerabilidades, los riesgos, los controles y las decisiones, no solo nuestra parte.
