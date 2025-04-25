<?php
session_start();
$conexion = new mysqli("localhost", "root", "", "wishield");

if ($conexion->connect_error) {
    die("Error de conexión: " . $conexion->connect_error);
}

$mensaje = "";

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $email = trim($_POST["email"]);
    $password = $_POST["password"];

    $stmt = $conexion->prepare("SELECT usuario_id, nombre, contraseña, rol FROM usuarios WHERE email = ?");
    $stmt->bind_param("s", $email);
    $stmt->execute();

    $resultado = $stmt->get_result();

    if ($resultado->num_rows === 1) {
        $usuario = $resultado->fetch_assoc();

        if (password_verify($password, $usuario["contraseña"])) {
            $_SESSION["usuario_id"] = $usuario["usuario_id"];
            $_SESSION["nombre"] = $usuario["nombre"];
            $_SESSION["rol"] = $usuario["rol"];
            $stmt_log = $conexion->prepare("INSERT INTO logs_acceso (usuario_id) VALUES (?)");
            $stmt_log->bind_param("i", $usuario["usuario_id"]);
            $stmt_log->execute();
            $stmt_log->close();
            header("Location: dashboard.php");
            exit;
        } else {
            $mensaje = "❌ Contraseña incorrecta.";
        }
    } else {
        $mensaje = "❌ No se encontró un usuario con ese email.";
    }

    $stmt->close();
}
?>

<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>Login WiShield</title>
    <style>
        body {
            font-family: Arial;
            background: #f1f2f6;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
        }
        .login-box {
            background: white;
            padding: 30px;
            border-radius: 12px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
            width: 300px;
        }
        input[type="email"], input[type="password"] {
            width: 100%;
            padding: 10px;
            margin: 12px 0;
            border-radius: 6px;
            border: 1px solid #ccc;
        }
        input[type="submit"] {
            background-color: #3498db;
            color: white;
            padding: 10px;
            border: none;
            width: 100%;
            border-radius: 6px;
            cursor: pointer;
        }
        .mensaje {
            margin-top: 10px;
            color: red;
            font-weight: bold;
        }
    </style>
</head>
<body>
    <div class="login-box">
        <h2>🔐 Login WiShield</h2>
        <form method="POST">
            <input type="email" name="email" placeholder="Correo electrónico" required>
            <input type="password" name="password" placeholder="Contraseña" required>
            <input type="submit" value="Iniciar sesión">
        </form>
        <?php if ($mensaje): ?>
            <div class="mensaje"><?php echo $mensaje; ?></div>
        <?php endif; ?>
    </div>
</body>
</html>
