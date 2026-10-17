# Sistema privado de legajos (Flask + PostgreSQL)

Esta versión es la adecuada como base para desplegar una aplicación con inicio de sesión y datos compartidos. **No está auditada ni debe considerarse automáticamente lista para producción con datos laborales sensibles.** Antes de importar legajos reales, la empresa debe aprobar el alojamiento, los accesos, la política de retención y las copias de seguridad.

## Estructura

- `app.py`: servidor Flask, autenticación, importación y API.
- `templates/`: interfaz HTML.
- `static/styles.css`: estilos CSS.
- `static/app.js`: comportamiento de la interfaz.
- `requirements.txt`: dependencias.
- `render.yaml`: plantilla opcional de despliegue con PostgreSQL.

## Despliegue sugerido: Render + PostgreSQL

1. Creá un repositorio **privado** en GitHub. Subí el contenido de esta carpeta a la raíz (no subas archivos de empleados ni `.env`).
2. En Render, elegí **New → Blueprint** y conectá el repositorio que contiene `render.yaml`, o creá un Web Service y una base PostgreSQL por separado.
3. Si usás `render.yaml`, revisá el plan/costo de la base y del servicio antes de confirmar. En las variables de entorno, completá `ADMIN_USERNAME` y `ADMIN_PASSWORD` con valores únicos. Usá una contraseña larga (mínimo 14 caracteres; idealmente más) y guardala en un gestor seguro.
4. Después del primer despliegue, inicializá la base y el primer administrador desde la Shell del servicio:
   - `flask --app app init-db`
   - Si hace falta crear más usuarios: `flask --app app create-user`
5. Configurá `COOKIE_SECURE=true` en producción. `SECRET_KEY` debe ser aleatoria y privada.
6. Verificá el inicio de sesión, importación, búsqueda, exportación y recuperación de copias de seguridad con un conjunto de prueba aprobado antes de usar datos reales.

**Importante:** la plantilla de Render puede tener costos; revisá precios y límites actuales. El servicio no queda protegido por el mero hecho de que el repositorio sea privado. El acceso a la aplicación lo controla el inicio de sesión; no publiques datos en GitHub.

## Desarrollo local

Instalá Python 3.11 o superior. En PowerShell, dentro de esta carpeta:

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
$env:SECRET_KEY = "cambia-esto-por-un-secreto-largo"
$env:COOKIE_SECURE = "false"
$env:ADMIN_USERNAME = "admin"
$env:ADMIN_PASSWORD = "cambia-esto-por-una-clave-larga-y-unica"
.\.venv\Scripts\python.exe -m flask --app app init-db
.\.venv\Scripts\python.exe -m flask --app app run
```

Abrí `http://127.0.0.1:5000`. En local usa SQLite. Para producción, definí `DATABASE_URL` con la URL privada de PostgreSQL de tu proveedor.

## Roles

- `admin`: puede consultar, importar y exportar.
- `viewer`: puede consultar fichas, pero no importar ni exportar.

Crear usuario desde terminal:

```powershell
.\.venv\Scripts\python.exe -m flask --app app create-user
```

## Importación

Admite `.xlsx`, `.xls` y `.csv`; lee la primera hoja de Excel. Se requiere una columna reconocible como `Legajo` o `Número de legajo`. Las columnas conocidas se muestran con etiquetas; las desconocidas se conservan en la ficha. Si el mismo legajo está en varios archivos, se combinan sus campos no vacíos.

## Antes de cargar legajos reales

- Confirmar con la empresa que el proveedor y la región de alojamiento están aprobados.
- Activar autenticación fuerte y administrar las altas/bajas de usuarios.
- Probar y programar copias de seguridad y restauración.
- Revisar las reglas de permisos para los campos sensibles.
- Definir quién puede exportar información.
- No enviar claves por chat ni incluirlas en GitHub.
- Considerar una revisión de seguridad independiente antes de uso productivo.
