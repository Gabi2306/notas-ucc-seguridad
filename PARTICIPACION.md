# Registro de participación

## Gabriela Zabaleta

Rol: coordinación, arquitectura y aplicación base.

Responsabilidades: selección y diseño de la aplicación, construcción de la versión vulnerable con las rutas `/login` y `/notas/<id>`, diagrama de arquitectura y flujo de datos, alcance autorizado, instrucciones de instalación y consolidación del informe ejecutivo.

Archivos: `app_vulnerable/app.py`, `README.md`, `requirements.txt`, `requirements-dev.txt`, `.gitignore`, `diagrama.md`, `evidencias/diagrama_flujo.png` e `informe/` (secciones 1 y 7, y consolidación).

Commits:

## Doris Arzuaga

Rol: análisis y mitigación.

Responsabilidades: caracterización de la inyección SQL y del BOLA, relación con OWASP, implementación de las correcciones (consulta parametrizada, hash de claves y verificación del dueño de la nota) y de los controles adicionales (lista blanca, límite de intentos, logs, cabeceras y errores genéricos).

Archivos: `app_corregida/app.py` e informe (secciones 2.1 y 4).

Commits:

## Jesús Egea

Rol: explotación controlada e integración continua.

Responsabilidades: pruebas de concepto de la inyección SQL (`' OR '1'='1` y `luis' --`) y del BOLA con dos sesiones, ejecución antes y después, generación de evidencias y configuración de la integración continua con pytest, bandit y pip-audit.

Archivos: `pruebas/pruebas.py`, `.github/workflows/seguridad.yml`, resultados y logs de `evidencias/` e informe (secciones 2.2 y 5).

Commits:

## Diego Luna

Rol: validación automatizada, riesgo y ética.

Responsabilidades: pruebas automatizadas de ataques, uso legítimo y controles adicionales, matriz de riesgo inicial y residual, reflexión ética, propuesta de seguridad en el ciclo de vida y el despliegue, y publicación técnica.

Archivos: `pruebas/test_seguridad.py`, `matrices.md`, `PUBLICACION.md`, `PARTICIPACION.md` e informe (secciones 3 y 6).

Commits:

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

## Dominio del proyecto

Todos los integrantes revisamos el proyecto completo y podemos explicar las dos vulnerabilidades, los riesgos, los controles y las decisiones, no solo nuestra parte.
