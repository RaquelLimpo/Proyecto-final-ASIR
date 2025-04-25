<?php
session_start();

if (!isset($_SESSION["usuario_id"]) || $_SESSION["rol"] !== "admin") {
    echo "<h2 style='color: red; text-align: center;'>⛔ Acceso denegado. Solo para administradores.</h2>";
    exit;
}

$conexion = new mysqli("localhost", "root", "", "wishield");
if ($conexion->connect_error) {
    die("Error de conexión: " . $conexion->connect_error);
}

$sql = "SELECT l.fecha_hora, u.nombre, u.email
        FROM logs_acceso l
        JOIN usuarios u ON l.usuario_id = u.usuario_id
        ORDER BY l.fecha_hora DESC";
$resultado = $conexion->query($sql);
?>

<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>Historial de Accesos · WiShield</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f4f6f9;
            margin: 0;
            padding: 0;
        }
        nav {
            background-color: #2c3e50;
            padding: 12px 20px;
            display: flex;
            gap: 20px;
        }
        nav a {
            color: #ecf0f1;
            text-decoration: none;
            font-weight: bold;
        }
        .container {
            max-width: 900px;
            margin: 30px auto;
            padding: 20px;
            background: white;
            border-radius: 12px;
            box-shadow: 0 3px 10px rgba(0,0,0,0.1);
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }
        th, td {
            border: 1px solid #ddd;
            padding: 10px;
        }
        th {
            background-color: #3498db;
            color: white;
        }
    </style>
</head>
<body>

<nav>
    <a href="wishield.php">🏠 Registro</a>
    <a href="dashboard.php">📊 Dashboard</a>
    <a href="logs.php">🕓 Logs de acceso</a>
    <span style="flex-grow: 1;"></span>
    <span style="color: #ecf0f1;">👤 <?php echo $_SESSION["nombre"]; ?> (<?php echo $_SESSION["rol"]; ?>)</span>
    <a href="logout.php">🚪 Cerrar sesión</a>
</nav>

<div class="container">
    <h2>🕓 Historial de accesos</h2>
    <table>
        <tr>
            <th>Nombre</th>
            <th>Email</th>
            <th>Fecha y hora de acceso</th>
        </tr>
        <?php while($fila = $resultado->fetch_assoc()): ?>
        <tr>
            <td><?php echo htmlspecialchars($fila['nombre']); ?></td>
            <td><?php echo htmlspecialchars($fila['email']); ?></td>
            <td><?php echo htmlspecialchars($fila['fecha_hora']); ?></td>
        </tr>
        <?php endwhile; ?>
    </table>
</div>

</body>
</html>
