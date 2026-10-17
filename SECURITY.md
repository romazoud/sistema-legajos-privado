# Seguridad y privacidad

Esta aplicación incluye inicio de sesión con contraseñas hasheadas, protección CSRF en formularios, cookies HTTPOnly/SameSite, roles básicos (admin y viewer), límite de 15 MB por solicitud y registro básico de acciones.

No es una auditoría de seguridad ni una garantía de cumplimiento legal. Para datos reales de empleados, la empresa debe revisar el proveedor de alojamiento, permisos por campo, políticas de acceso, registros, recuperación de cuenta, backups, retención y obligaciones legales aplicables. No subas legajos ni exportaciones al repositorio. Las credenciales deben mantenerse como variables de entorno, nunca en el código.

El importador conserva columnas adicionales en la base de datos; por eso, no importes datos sensibles innecesarios sin aprobar previamente qué campos deben almacenarse y quién puede consultarlos.
