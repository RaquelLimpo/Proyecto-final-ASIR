<?php
require_once 'config.php';
$conexion = new mysqli("localhost", "root", "", "wishield");

// Datos simulados para test
$nombre = "Procedimiento Test";
$email = "proc_test@example.com";
$password = password_hash("segura123", PASSWORD_BCRYPT);
$rol = "invitado";
$mac = "00:11:22:33:44:55";
$ip = "192.168.0.250";
$tipo = "Smartphone";

$stmt = $conexion->prepare("CALL sp_insertar_usuario(?, ?, ?, ?, ?, ?, ?, ?)");
$stmt->bind_param("ssssssss",
    $nombre,
    $email,
    $password,
    $rol,
    $mac,
    $ip,
    $tipo,
    CLAVE_SECRETA
);
$stmt->execute();
$resultado = $stmt->get_result();

if ($resultado && $fila = $resultado->fetch_assoc()) {
    echo "✅ Usuario insertado con ID: " . $fila['nuevo_usuario_id'];
} else {
    echo "❌ Algo salió mal al insertar.";
}
?>
