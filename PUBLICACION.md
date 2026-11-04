# Dos líneas de código, dos formas de exponer a tus usuarios: inyección SQL y BOLA en una API de notas

Doris Arzuaga, Jesús Egea, Diego Luna y Gabriela Zabaleta. Proyecto final de Optativa.

## El problema

Construimos Notas UCC, una API pequeña en Flask y SQLite en la que un estudiante inicia sesión y consulta sus calificaciones. Tiene solo dos rutas, `POST /login` y `GET /notas/<id>`, y aun así cometimos a propósito dos errores muy comunes en aplicaciones reales: una inyección SQL en el login, que es un error de implementación, y un BOLA (Broken Object Level Authorization) en la consulta de notas, que es un error de diseño.

Todo se probó únicamente en `127.0.0.1`, con datos ficticios.

## Vulnerabilidad 1: cuando el dato se vuelve código

```python
consulta = f"SELECT id, usuario FROM usuarios WHERE usuario = '{usuario}' AND clave = '{clave}'"
```

Si alguien escribe como clave `' OR '1'='1`, la condición queda `(usuario='ana' AND clave='') OR '1'='1'`. Como `AND` se evalúa antes que `OR`, la condición es verdadera para todas las filas y la persona entra sin clave. Si escribe `luis' --` como usuario, el `--` comenta el resto de la consulta y la sesión se abre como luis, así que el atacante puede elegir a quién suplantar.

Es la categoría A05:2025 Injection del OWASP Top 10 (A03 en la edición 2021), porque un dato no confiable termina interpretado como parte de un comando.

La corrección no consiste en filtrar comillas, sino en separar el código de los datos:

```python
fila = db.execute("SELECT id, usuario, clave_hash FROM usuarios WHERE usuario = ?", (usuario,)).fetchone()
if fila and check_password_hash(fila["clave_hash"], clave):
```

Con el parámetro `?` el motor recibe la consulta y el valor por separado, y el valor ya no puede cambiar la estructura del SQL. De paso, las claves quedaron guardadas como hash.

## Vulnerabilidad 2: autenticado no es lo mismo que autorizado

```python
nota = db.execute("SELECT * FROM notas WHERE id = ?", (nota_id,)).fetchone()
return jsonify({"ok": True, "nota": dict(nota)})
```

Esta consulta sí está parametrizada, así que no hay inyección. El problema es otro: la ruta solo comprueba que haya una sesión y nunca revisa que la nota sea de quien la pide. Luis inicia sesión, pide `/notas/2` y recibe la nota de Ana. Como los números son consecutivos, basta con recorrerlos.

Es la categoría API1:2023 del OWASP API Security Top 10. El control se queda en preguntar quién eres y nunca pregunta si el objeto es tuyo.

La corrección:

```python
if nota["usuario_id"] != session["usuario_id"]:
    return jsonify({"ok": False, "error": "No autorizado"}), 403
```

## Más de una capa

Un solo control puede fallar, así que la versión corregida agrega otras protecciones: validación del nombre de usuario con una lista blanca, límite de cinco intentos fallidos, registro de eventos de seguridad sin guardar claves, clave de sesión tomada del entorno y no del código, cookie protegida, cabeceras de seguridad y mensajes de error que no revelan detalles internos.

## Antes y después

En la versión vulnerable, `' OR '1'='1` permite entrar sin clave, `luis' --` permite entrar como luis y luis puede leer la nota de Ana. Además, se pueden probar claves sin límite.

En la versión corregida, los dos ataques de inyección reciben 401, la nota ajena recibe 403 y queda registrada, y desde el sexto intento fallido el login responde 429. Leer la nota propia funciona igual en ambas versiones.

La prueba de concepto dio 16 de 16 casos correctos y las pruebas automatizadas 18 de 18. La herramienta de análisis estático bandit detecta el SQL armado con f-string y la clave fija en la versión vulnerable, y no encuentra nada en la corregida. Todo esto se ejecuta en GitHub Actions con cada cambio, de modo que si alguien vuelve a introducir el fallo, se nota de inmediato.

El riesgo bajó de crítico a medio en la inyección y de alto a bajo en el BOLA.

## La pregunta incómoda

¿Desplegarías con la vulnerabilidad para cumplir la fecha y la corregirías después? Nuestra respuesta es no. El costo de esa decisión no lo paga el equipo que la toma, sino estudiantes que nunca sabrían que alguien vio sus notas. En Colombia, además, las calificaciones son datos personales protegidos por la Ley 1581 de 2012. Y cada corrección costó menos de diez líneas de código. Postergar solo sería defendible con un riesgo bajo, documentado y aceptado por quien asume las consecuencias, y una suplantación de identidad o una fuga de datos personales no cumple esas condiciones.

## Lo que nos llevamos

Una consulta parametrizada no es un detalle de estilo: es lo que separa el dato del código.

La autenticación responde quién eres. La autorización tiene que responder qué puedes ver, en cada petición y para cada objeto.

La seguridad tiene que estar en todo el ciclo de vida: casos de abuso en los requisitos, reglas de autorización en el diseño, revisión de código, pruebas de ataque automatizadas y un pipeline que detenga los cambios inseguros.

Repositorio: https://github.com/Gabi2306/notas-ucc-seguridad

Referencias: OWASP Top 10:2025; OWASP API Security Top 10 (2023); OWASP Cheat Sheets de SQL Injection Prevention, Authorization y Password Storage; Ley 1581 de 2012.
