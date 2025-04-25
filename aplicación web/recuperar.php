<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>Recuperar contraseña</title>
</head>
<body>
    <h2>🔐 ¿Olvidaste tu contraseña?</h2>
    <form method="POST" action="enviar_token.php">
        <label>Introduce tu email:
            <input type="email" name="email" required>
        </label>
        <br><br>
        <input type="submit" value="Enviar enlace de recuperación">
    </form>
</body>
</html>
