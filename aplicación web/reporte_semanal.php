<?php
require 'src/PHPMailer.php';
require 'src/SMTP.php';
require 'src/Exception.php';
require 'language/phpmailer.lang-es.php';

use PHPMailer\PHPMailer\PHPMailer;

$conexion = new mysqli("localhost", "root", "", "wishield");

if ($conexion->connect_error) {
    die("Error de conexión: " . $conexion->connect_error);
}

// Consultas
$nuevos_usuarios = $conexion->query("SELECT COUNT(*) AS total FROM usuarios WHERE fecha_creacion >= CURDATE() - INTERVAL 7 DAY")->fetch_assoc()['total'];
$nuevas_sesiones = $conexion->query("SELECT COUNT(*) AS total FROM Sesiones_Conexion WHERE timestamp_inicio >= CURDATE() - INTERVAL 7 DAY")->fetch_assoc()['total'];
$nuevas_vulnerabilidades = $conexion->query("SELECT COUNT(*) AS total FROM Vulnerabilidades WHERE fecha_deteccion >= CURDATE() - INTERVAL 7 DAY")->fetch_assoc()['total'];

// Obtener correos de administradores
$correos = [];
$result = $conexion->query("SELECT email FROM usuarios WHERE rol = 'admin'");
while ($row = $result->fetch_assoc()) {
    $correos[] = $row['email'];
}
$conexion->close();

// HTML del correo
$fecha = date('Y-m-d');
$reporteHTML = "
    <h2>📊 Reporte Semanal WiShield - $fecha</h2>
    <ul>
        <li>👥 Nuevos usuarios registrados: <strong>$nuevos_usuarios</strong></li>
        <li>🔌 Sesiones iniciadas: <strong>$nuevas_sesiones</strong></li>
        <li>🛡️ Vulnerabilidades detectadas: <strong>$nuevas_vulnerabilidades</strong></li>
    </ul>
    <p style='color: #888;'>Enviado automáticamente por el sistema WiShield</p>
";

// Envío del correo
$mail = new PHPMailer(true);

try {
    $mail->isSMTP();
    $mail->Host       = 'smtp.gmail.com';
    $mail->SMTPAuth   = true;
    $mail->Username   = 'tuemail@gmail.com';         // <- tu email real
    $mail->Password   = 'contraseña_de_aplicacion';  // <- tu contraseña de aplicación
    $mail->SMTPSecure = 'tls';
    $mail->Port       = 587;
    $mail->CharSet    = 'UTF-8';

    $mail->setFrom('tuemail@gmail.com', 'Sistema WiShield');

    foreach ($correos as $correo) {
        $mail->addAddress($correo);
    }

    $mail->isHTML(true);
    $mail->Subject = "📋 Reporte semanal WiShield ($fecha)";
    $mail->Body    = $reporteHTML;

    $mail->send();
    echo "✅ Reporte enviado correctamente a administradores.";
} catch (Exception $e) {
    echo "❌ Error al enviar el reporte: {$mail->ErrorInfo}";
}
?>
