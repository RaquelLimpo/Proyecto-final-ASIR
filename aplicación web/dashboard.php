<?php
ob_start();
session_start();
$_SESSION["usuario_id"] = 1;
$_SESSION["nombre"] = "Admin Temporal";
$_SESSION["rol"] = "admin";

// Control de IPs autorizadas
//$ips_autorizadas = ['127.0.0.1', '::1']; // Añade otras IPs si lo ves necesario
//$ip_actual = $_SERVER['REMOTE_ADDR'];
//if (!in_array($ip_actual, $ips_autorizadas)) {
 //   header("HTTP/1.1 403 Forbidden");
  //  echo "<h1 style='color: red;'>⛔ Acceso denegado</h1>";
  //  echo "<p>IP bloqueada: <strong>$ip_actual</strong></p>";
  //  exit;
//}

if (!isset($_SESSION["usuario_id"])) {
    header("Location: login.php");
    exit;
}

require_once 'config.php';
$conexion = new mysqli("localhost", "root", "", "wishield");

if ($conexion->connect_error) {
    die("Error de conexión: " . $conexion->connect_error);
}

// Usuarios por rol
$res_usuarios = $conexion->query("CALL sp_total_por_rol()");
$usuarios_data = [];
while ($row = $res_usuarios->fetch_assoc()) {
    $usuarios_data[] = $row;
}
$res_usuarios->close();
$conexion->next_result();

// Sesiones activas por red
$res_sesiones = $conexion->query("CALL sp_sesiones_activas()");
$sesiones_data = [];
while ($row = $res_sesiones->fetch_assoc()) {
    $sesiones_data[] = $row;
}
$res_sesiones->close();
$conexion->next_result();

// Vulnerabilidades por severidad
$res_vuln = $conexion->query("CALL sp_total_vulnerabilidades()");
$vuln_data = [];
while ($row = $res_vuln->fetch_assoc()) {
    $vuln_data[] = $row;
}
$res_vuln->close();
$conexion->next_result();

// Logs por usuario (NO cerrar aún, lo haces en el HTML)
$res_logs = $conexion->query("CALL sp_logs_por_usuario()");
$conexion->next_result(); // Dejar esto para liberar el siguiente CALL

// Actividad por fecha (igual)
$res_actividad = $conexion->query("CALL sp_actividad_por_fecha()");
$conexion->next_result();

// Dispositivos conectados por tipo
$res_disp = $conexion->query("CALL sp_dispositivos_por_tipo()");
$tipos = [];
$valores = [];
while ($fila = $res_disp->fetch_assoc()) {
    $tipos[] = $fila['tipo_dispositivo'];
    $valores[] = $fila['total'];
}
$res_disp->close();
$conexion->next_result();

$conexion->close();
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>Dashboard WiShield</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body {
            font-family: Arial, sans-serif;
            background: #f0f4f8;
            padding: 20px;
        }

        nav {
            background: #2c3e50;
            padding: 12px;
            display: flex;
            gap: 20px;
        }

        nav a {
            color: #ecf0f1;
            text-decoration: none;
            font-size: 16px;
        }

        .chart-row {
            display: flex;
            flex-wrap: wrap;
            gap: 20px;
            justify-content: center;
        }

        .chart-container {
            background: white;
            padding: 20px;
            border-radius: 12px;
            box-shadow: 0 4px 10px rgba(0,0,0,0.1);
            width: 350px;
        }

        canvas {
            max-width: 100%;
        }

        h1 {
            text-align: center;
            color: #2c3e50;
        }
    </style>
</head>
<body>
    <nav>
        <a href="wishield.php">🏠 Registro</a>
        <a href="dashboard.php">📊 Dashboard</a>
        <a href="https://localhost/phpmyadmin" target="_blank">🛠 phpMyAdmin</a>
        <span style="flex-grow: 1;"></span>
        <span style="color: #ecf0f1;">👤 <?php echo $_SESSION["nombre"] . " (" . $_SESSION["rol"] . ")"; ?></span>
        <a href="logout.php" style="margin-left: 20px;">🚪 Cerrar sesión</a>
    </nav>

    <h1>📊 Dashboard WiShield</h1>

    <div class="chart-row">
        <div class="chart-container">
            <h3>🧑‍🤝‍🧑 Usuarios por rol</h3>
            <canvas id="usuariosChart"></canvas>
        </div>
        <div class="chart-container">
            <h3>📶 Sesiones activas por red</h3>
            <canvas id="sesionesChart"></canvas>
        </div>
        <div class="chart-container">
            <h3>🔐 Vulnerabilidades por severidad</h3>
            <canvas id="vulnChart"></canvas>
        </div>
        <div class="chart-container">
            <h3>📱 Dispositivos por tipo</h3>
            <canvas id="graficaDispositivos"></canvas>
        </div>
    </div>

    <h3>📜 Últimos accesos de usuarios</h3>
    <table border='1' cellpadding='6' style='border-collapse: collapse; background: white;'>
        <tr style='background: #34495e; color: white;'>
            <th>Usuario</th><th>Email</th><th>Último acceso</th>
        </tr>
        <?php while ($fila = $res_logs->fetch_assoc()): ?>
        <tr>
            <td><?php echo htmlspecialchars($fila['nombre']); ?></td>
            <td><?php echo htmlspecialchars($fila['email']); ?></td>
            <td><?php echo $fila['ultima_conexion'] ?? '—'; ?></td>
        </tr>
        <?php endwhile; $res_logs->close(); ?>
    </table>

    <h3>📅 Actividad (últimos 7 días)</h3>
    <table border='1' cellpadding='6' style='border-collapse: collapse; background: white;'>
        <tr style='background: #2ecc71; color: white;'>
            <th>Fecha</th><th>Sesiones iniciadas</th>
        </tr>
        <?php while ($fila = $res_actividad->fetch_assoc()): ?>
        <tr>
            <td><?php echo $fila['fecha']; ?></td>
            <td><?php echo $fila['sesiones']; ?></td>
        </tr>
        <?php endwhile; $res_actividad->close(); ?>
    </table>

    <script>
        const usuariosData = <?php echo json_encode($usuarios_data); ?>;
        const sesionesData = <?php echo json_encode($sesiones_data); ?>;
        const vulnData     = <?php echo json_encode($vuln_data); ?>;
        const tiposDisp    = <?php echo json_encode($tipos); ?>;
        const valoresDisp  = <?php echo json_encode($valores); ?>;

        new Chart(document.getElementById('usuariosChart'), {
            type: 'pie',
            data: {
                labels: usuariosData.map(x => x.rol),
                datasets: [{
                    data: usuariosData.map(x => x.total),
                    backgroundColor: ['#3498db', '#2ecc71', '#f1c40f']
                }]
            }
        });

        new Chart(document.getElementById('sesionesChart'), {
            type: 'bar',
            data: {
                labels: sesionesData.map(x => x.red),
                datasets: [{
                    label: 'Sesiones activas',
                    data: sesionesData.map(x => x.total),
                    backgroundColor: '#9b59b6'
                }]
            }
        });

        new Chart(document.getElementById('vulnChart'), {
            type: 'doughnut',
            data: {
                labels: vulnData.map(x => x.severidad),
                datasets: [{
                    data: vulnData.map(x => x.total),
                    backgroundColor: ['#e74c3c', '#f39c12', '#27ae60', '#34495e']
                }]
            }
        });

        new Chart(document.getElementById('graficaDispositivos'), {
            type: 'bar',
            data: {
                labels: tiposDisp,
                datasets: [{
                    label: 'Cantidad',
                    data: valoresDisp,
                    backgroundColor: ['#3498db', '#9b59b6', '#f1c40f', '#2ecc71', '#e74c3c'],
                    borderColor: '#2c3e50',
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: { display: false }
                },
                scales: {
                    y: { beginAtZero: true }
                }
            }
        });
    </script>
</body>
</html>
<?php ob_end_flush(); ?>
