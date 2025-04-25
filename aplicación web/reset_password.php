<?php
require_once 'config.php';

$conexion = new mysqli("localhost", "root", "", "wishield");

$token = $_GET['token'] ?? '';
$valido = false;

// Verificar token válido y no caducado
$stmt = $conexion->prepare("SELECT usuario_id FROM tokens_recuperacion 
                            WHERE token = ? AND expiracion > NOW()");
$stmt->bind_param("s", $token);
$stmt->execute();
$resultado = $stmt->get_result();

if ($resultado->num_rows === 1) {
    $valido = true;
    $usuario = $resultado->fetch_assoc();
    $usuario_id = $usuario['usuario_id'];
}

if ($_SERVER["REQUEST_METHOD"] === "POST" && isset($_POST["nueva_contraseña"])) {
    $nueva_contraseña = password_hash($_POST["nueva_contraseña"], PASSWORD_BCRYPT);

    // Actualizar contraseña
    $update = $conexion->prepare("UPDATE usuarios SET contraseña = ? WHERE usuario_id = ?");
    $update->bind_param("si", $nueva_contraseña, $_POST['usuario_id']);
    $update->execute();

    // Eliminar token
    $delete = $conexion->prepare("DELETE FROM tokens_recuperacion WHERE usuario_id = ?");
    $delete->bind_param("i", $_POST['usuario_id']);
    $delete->execute();

    echo "<h3 style='color:green;'>✅ Tu contraseña se ha actualizado correctamente. Ya puedes iniciar sesión.</h3>";
    exit;
}
?>

<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>Restablecer contraseña</title>
</head>
<body>
    <h2>🔐 Restablecer contraseña</h2>

    <?php if ($valido): ?>
        <form method="POST">
            <input type="hidden" name="usuario_id" value="<?php echo $usuario_id; ?>">
            <label>Nueva contraseña:
                <input type="password" name="nueva_contraseña" required>
            </label><br><br>
            <input type="submit" value="Actualizar contraseña">
        </form>
    <?php else: ?>
        <p style="color:red;">⛔ Este enlace no es válido o ha expirado.</p>
    <?php endif; ?>
</body>
</html>
