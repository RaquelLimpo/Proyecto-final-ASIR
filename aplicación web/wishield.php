<?php
session_start();

$_SESSION["usuario_id"] = 1;
$_SESSION["nombre"] = "Admin Temporal";
$_SESSION["rol"] = "admin";

// Control de IPs autorizadas
//$ips_autorizadas = [$ip_actual]; // Añade otras IPs si lo ves necesario
//$ip_actual = $_SERVER['REMOTE_ADDR'];
//if (!in_array($ip_actual, $ips_autorizadas)) {
  //  header("HTTP/1.1 403 Forbidden");
    //echo "<h1 style='color: red;'>⛔ Acceso denegado</h1>";
    //echo "<p>IP bloqueada: <strong>$ip_actual</strong></p>";
    //exit;
//}

require_once 'config.php'; // Clave secreta para AES

// Proteger acceso solo para admins
if (!isset($_SESSION["usuario_id"])) {
  header("Location: login.php");
   exit;
}
if ($_SESSION["rol"] !== "admin") {
    echo "<h2 style='color: red; text-align: center;'>⛔ Acceso denegado. Solo para administradores.</h2>";
    exit;
}

// Activar errores 
ini_set('display_errors', 1);
error_reporting(E_ALL);
mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);

// Conexión
$conexion = new mysqli("localhost", "root", "", "wishield");
if ($conexion->connect_error) {
    die("Error de conexión: " . $conexion->connect_error);
}

// Paginación
$registros_por_pagina = 20;
$pagina_actual = isset($_GET['pagina']) ? (int)$_GET['pagina'] : 1;
$offset = ($pagina_actual - 1) * $registros_por_pagina;

// Procesar formulario
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $nombre = trim($_POST['nombre']);
    $email  = trim($_POST['email']);
    $password = password_hash($_POST['password'], PASSWORD_BCRYPT);
    $rol    = trim($_POST['rol']);
    $tipo_dispositivo = trim($_POST['tipo_dispositivo']);
    $mac_address = trim($_POST['mac_address']);
    $ip_address = trim($_POST['ip_address']);

    // Insertar usuario
    $sql = "INSERT INTO usuarios (nombre, email, rol, contraseña) VALUES (?, ?, ?, ?)";
    $stmt = $conexion->prepare($sql);
    $stmt->bind_param("ssss", $nombre, $email, $rol, $password);

    if ($stmt->execute()) {
        $usuario_id = $conexion->insert_id;

        // Insertar dispositivo con cifrado AES
        $sql_dispositivo = "INSERT INTO Dispositivos (usuario_id, mac_address, ip_address, tipo_dispositivo)
                            VALUES (?, AES_ENCRYPT(?, ?), AES_ENCRYPT(?, ?), ?)";
        $stmt2 = $conexion->prepare($sql_dispositivo);
        $stmt2->bind_param("isssss", $usuario_id, $mac_address, CLAVE_SECRETA, $ip_address, CLAVE_SECRETA, $tipo_dispositivo);
        $stmt2->execute();

        // Comprobar vulnerabilidades
        $sql_vuln = "SELECT * FROM Vulnerabilidades WHERE dispositivo_id IN (
                        SELECT id FROM Dispositivos WHERE usuario_id = ?)";
        $stmt3 = $conexion->prepare($sql_vuln);
        $stmt3->bind_param("i", $usuario_id);
        $stmt3->execute();
        $result = $stmt3->get_result();

        echo "<div style='color:green; margin: 10px;'>Usuario y dispositivo registrados correctamente.</div>";
        if ($result->num_rows > 0) {
            echo "<div style='color:red; margin: 10px;'>¡Este usuario tiene dispositivos vulnerables!</div>";
        }

        $stmt2->close();
        $stmt3->close();
    } else {
        echo "Error al agregar usuario: " . $stmt->error;
    }

    $stmt->close();
}

// Filtro de búsqueda
$condicion = "";
if (isset($_GET['buscar']) && $_GET['buscar'] !== "") {
    $buscar = $conexion->real_escape_string($_GET['buscar']);
    $condicion = "WHERE u.nombre LIKE '%$buscar%' OR u.rol LIKE '%$buscar%'";
}

// Total para paginación
$sql_total = "SELECT COUNT(*) as total FROM usuarios u
              JOIN Dispositivos d ON u.usuario_id = d.usuario_id
              $condicion";
$res_total = $conexion->query($sql_total);
$total_filas = $res_total->fetch_assoc()['total'];
$total_paginas = ceil($total_filas / $registros_por_pagina);

$sql = "SELECT u.nombre, u.email, u.rol,
               d.tipo_dispositivo,
               d.mac_address,
               d.ip_address
        FROM usuarios u
        JOIN Dispositivos d ON u.usuario_id = d.usuario_id
        $condicion
        ORDER BY u.usuario_id DESC
        LIMIT $registros_por_pagina OFFSET $offset";

$resultado = $conexion->query($sql);

if (!$resultado) {
    die("❌ Error en la consulta de usuarios: " . $conexion->error);
}

?>


<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>WiShield · Registro de Usuarios</title>
    <style>
        body {
            font-family: 'Segoe UI', sans-serif;
            background-color: #f2f4f8;
            margin: 0;
            padding: 0;
        }

        nav {
            background: #2c3e50;
            padding: 12px 20px;
            display: flex;
            gap: 20px;
        }

        nav a {
            color: #ecf0f1;
            text-decoration: none;
            font-weight: bold;
        }

        h2, h3 {
            color: #2c3e50;
        }

        .container {
            max-width: 1000px;
            margin: 30px auto;
            padding: 0 20px;
        }

        .card {
            background-color: white;
            padding: 20px;
            border-radius: 12px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            margin-bottom: 30px;
        }

        form label {
            display: block;
            margin-bottom: 12px;
        }

        input[type="text"],
        input[type="email"],
        select {
            width: 100%;
            padding: 10px;
            border-radius: 6px;
            border: 1px solid #ccc;
            margin-top: 5px;
        }

        input[type="submit"] {
            background-color: #3498db;
            color: white;
            border: none;
            padding: 10px 16px;
            border-radius: 6px;
            font-weight: bold;
            cursor: pointer;
            margin-top: 10px;
        }

        input[type="submit"]:hover {
            background-color: #2980b9;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            background-color: white;
        }

        th, td {
            padding: 10px;
            border: 1px solid #ddd;
            text-align: left;
        }

        th {
            background-color: #2980b9;
            color: white;
        }

        .search-box {
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
        }

        .search-box input[type="text"] {
            flex: 1;
        }
    </style>
</head>
<body>

<nav>
    <a href="wishield.php">🏠 Registro</a>
    <a href="dashboard.php">📊 Dashboard</a>
    <a href="http://localhost/phpmyadmin" target="_blank">🛠 phpMyAdmin</a>
    <span style="flex-grow: 1;"></span>
    <span style="color: #ecf0f1;">👤 <?php echo $_SESSION["nombre"]; ?> (<?php echo $_SESSION["rol"]; ?>)</span>
    <a href="logout.php" style="margin-left: 20px;">🚪 Cerrar sesión</a>
</nav>

<div class="container">

    <div class="card">
        <form method="GET" class="search-box">
            <input type="text" name="buscar" placeholder="Buscar por nombre o rol..." 
                   value="<?php echo isset($_GET['buscar']) ? htmlspecialchars($_GET['buscar']) : ''; ?>">
            <input type="submit" value="Buscar">
        </form>
    </div>

    <div class="card">
        <h2>Agregar nuevo usuario + dispositivo</h2>
        <form method="POST">
            <label>Nombre:
                <input type="text" name="nombre" required>
            </label>
            <label>Email:
                <input type="email" name="email" required>
            </label>
            <label>Contraseña:
             <input type="password" name="password" required>
             </label>

            <label>Rol:
                <select name="rol">
                    <option value="invitado">Invitado</option>
                    <option value="estudiante">Estudiante</option>
                    <option value="admin">Administrador</option>
                </select>
            </label>
            <label>Tipo de dispositivo:
                <select name="tipo_dispositivo">
                    <option value="Laptop">Laptop</option>
                    <option value="Smartphone">Smartphone</option>
                    <option value="Tablet">Tablet</option>
                    <option value="Smart TV">Smart TV</option>
                    <option value="Smartwatch">Smartwatch</option>
                    <option value="Consola de videojuegos">Consola de videojuegos</option>
                </select>
            </label>
            <label>MAC Address:
                <input type="text" name="mac_address" required>
            </label>
            <label>IP Address:
                <input type="text" name="ip_address" required>
            </label>
            <input type="submit" value="Agregar Usuario">
        </form>
    </div>

    <div class="card">
    <h3>📋 Usuarios registrados y sus dispositivos</h3>
    <table>
        <tr>
            <th>Nombre</th>
            <th>Email</th>
            <th>Rol</th>
            <th>Tipo de Dispositivo</th>
            <th>MAC Address</th>
            <th>IP Address</th>
        </tr>
        <?php while ($fila = $resultado->fetch_assoc()): ?>
        <tr>
            <td><?php echo htmlspecialchars($fila['nombre']); ?></td>
            <td><?php echo htmlspecialchars($fila['email']); ?></td>
            <td><?php echo htmlspecialchars($fila['rol']); ?></td>
            <td><?php echo htmlspecialchars($fila['tipo_dispositivo']); ?></td>
            <td><?php echo htmlspecialchars($fila['mac_address']); ?></td>
            <td><?php echo htmlspecialchars($fila['ip_address']); ?></td>
        </tr>
        <?php endwhile; ?>
    </table>
</div>
        <div style="text-align: center; margin-top: 20px;">
    <?php if ($pagina_actual > 1): ?>
        <a href="?pagina=<?php echo $pagina_actual - 1; ?>&buscar=<?php echo urlencode($_GET['buscar'] ?? ''); ?>">« Anterior</a>
    <?php endif; ?>

    <?php for ($i = 1; $i <= $total_paginas; $i++): ?>
        <a href="?pagina=<?php echo $i; ?>&buscar=<?php echo urlencode($_GET['buscar'] ?? ''); ?>"
           style="<?php echo ($i == $pagina_actual) ? 'font-weight: bold; text-decoration: underline;' : ''; ?>">
           <?php echo $i; ?>
        </a>
    <?php endfor; ?>

    <?php if ($pagina_actual < $total_paginas): ?>
        <a href="?pagina=<?php echo $pagina_actual + 1; ?>&buscar=<?php echo urlencode($_GET['buscar'] ?? ''); ?>">Siguiente »</a>
    <?php endif; ?>
</div>

    </div>

</div>
</body>
</html>

