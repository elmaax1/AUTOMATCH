AUTOMATCH - PROTOTIPO WEB V1
============================

NOTA: Este documento describe el prototipo local inicial. La aplicación actual
usa PostgreSQL y Supabase Storage; las instrucciones de SQLite y almacenamiento
local que siguen ya no describen el despliegue actual.

Qué incluye:
- Catálogo de vehículos compartido dentro de la aplicación local.
- Publicación de autos, motos, camionetas, utilitarios, camiones y otros.
- Carga de fotografías (JPG, JPEG, PNG, WEBP).
- Búsqueda por marca, modelo o localidad.
- Filtros por categoría y precio máximo.
- Opción de aceptar permutas.
- Contacto por WhatsApp y correo.
- Orden de publicaciones destacadas (preparado en la base de datos).

REQUISITOS
- Windows 10/11
- Python 3.10 o superior
- Visual Studio Code (recomendado)

INSTALACIÓN EN WINDOWS
1. Extraé automatch_v1.zip en una carpeta, por ejemplo Documentos\AUTOMATCH.
2. Abrí esa carpeta en Visual Studio Code.
3. Abrí Terminal > New Terminal.
4. Ejecutá:
   py -m venv .venv
   .venv\Scripts\activate
   py -m pip install -r requirements.txt
5. Iniciá la aplicación:
   py app.py
6. Abrí tu navegador en:
   http://127.0.0.1:5000

DETENER
- En la terminal de VS Code presioná Ctrl+C.

DATOS
- La base de datos automatch.db se crea automáticamente.
- Las fotografías se guardan en la carpeta uploads.
- No borres automatch.db ni uploads si querés conservar tus publicaciones.

IMPORTANTE
Esta es una versión de prueba local, no una plataforma pública en Internet.
Todavía no incluye cuentas y autenticación, chat interno, pagos reales,
moderación administrativa ni despliegue online.
El campo de publicaciones destacadas está preparado en la base de datos,
pero la compra y activación de destacados todavía no está conectada a pagos.
No uses datos personales reales ni publiques esta versión sin revisión de seguridad.
Antes de producción hay que configurar una clave secreta segura, validación
adicional de archivos, autenticación, protección contra spam y copias de seguridad.

CONFIGURACIÓN ACTUAL PARA RENDER
- Configurá AUTOMATCH_ENV=production en el servicio de producción.
- AUTOMATCH_SECRET_KEY es obligatorio en producción y debe conservar el mismo
  valor entre reinicios e instancias. El archivo .automatch_secret se usa como
  alternativa únicamente fuera de producción.
- Para probar Mercado Pago, usá un servicio de pruebas separado con
  AUTOMATCH_ENV=test, credenciales sandbox y base de datos/almacenamiento
  aislados. El servicio de producción solo procesa notificaciones live_mode=true.
- No guardes valores secretos en este archivo ni en el repositorio.
