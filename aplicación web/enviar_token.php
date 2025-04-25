<?php
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

require 'src/PHPMailer.php';
require 'src/SMTP.php';
require 'src/Exception.php';
require_once 'config.php';

$conexion = new mysqli("localhost", "root", "", "wishield");

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $email = trim($_POST['email']);

    // Buscar usuario por email
    $stmt = $conexion->prepare("SELECT usuario_id, nombre FROM usuarios WHERE email = ?");
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $resultado = $stmt->get_result();

    if ($resultado->num_rows === 1) {
        $usuario = $resultado->fetch_assoc();
        $usuario_id = $usuario["usuario_id"];
        $nombre = $usuario["nombre"];

        // Generar token y caducidad (ej. 1 hora)
        $token = bin2hex(random_bytes(32));
        $expiracion = date("Y-m-d H:i:s", strtotime("+1 hour"));

        // Guardar en base de datos
        $insert = $conexion->prepare("INSERT INTO tokens_recuperacion (usuario_id, token, expiracion) VALUES (?, ?, ?)");
        $insert->bind_param("iss", $usuario_id, $token, $expiracion);
        $insert->execute();

        // Crear enlace
        $enlace = "http://localhost/wishield/reset_password.php?token=$token";

        // Configurar PHPMailer
        $mail = new PHPMailer(true);
        try {
            $mail->isSMTP();
            $mail->Host = 'smtp.gmail.com';
            $mail->SMTPAuth = true;
            $mail->Username = 'astoreth@gmail.com'; // 👈 Pon tu correo
            $mail->Password = 'xfad nfmr gqnn mjqb'; // 👈 Aquí tu contraseña de aplicación
            $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
            $mail->Port = 587;

            $mail->setFrom('Tastoreth@gmail.com', 'WiShield');
            $mail->addAddress($email, $nombre);
            $mail->isHTML(true);
            $mail->Subject = '🔐 Recuperación de contraseña WiShield';
            $mail->Body = "Hola <strong>$nombre</strong>,<br><br>
                           Has solicitado recuperar tu contraseña.<br>
                           <a href='$enlace'>Haz clic aquí para crear una nueva contraseña</a><br><br>
                           Este enlace caduca en 1 hora.";

            $mail->send();
            echo "<h3 style='color:green;'>✅ Se ha enviado un correo con instrucciones de recuperación.</h3>";
        } catch (Exception $e) {
            echo "<h3 style='color:red;'>❌ Error al enviar el correo: {$mail->ErrorInfo}</h3>";
        }
    } else {
        echo "<h3 style='color:red;'>❌ No se encontró ninguna cuenta con ese email.</h3>";
    }
}
?>
