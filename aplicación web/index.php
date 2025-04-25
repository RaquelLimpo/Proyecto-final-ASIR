<?php
session_start();
?>

<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>WiShield · Inicio</title>
    <style>
        body {
            font-family: 'Segoe UI', sans-serif;
            background: #ecf0f1;
            margin: 0;
            padding: 0;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            height: 100vh;
        }

        .card {
            background: white;
            padding: 30px 40px;
            border-radius: 12px;
            box-shadow: 0 4px 15px rgba(0,0,0,0.1);
            text-align: center;
        }

        h1 {
            margin-bottom: 20px;
            color: #2c3e50;
        }

        a {
            display: block;
            margin: 10px 0;
            padding: 12px 18px;
            background: #3498db;
            color: white;
            text-decoration: none;
            border-radius: 6px;
            font-weight: bold;
            transition: background 0.2s ease;
        }

        a:hover {
            background: #2980b9;
        }

        .info {
            margin-top: 20px;
            color: #555;
        }

    </style>
</head>
<body>

<div class="card">
    <h1>🔐 WiShield - Panel Principal</h1>

    <?php if (!isset($_SESSION["usuario_id"])): ?>
        <a href="login.php">Iniciar sesión</a>
    <?php else: ?>
        <a href="dashboard.php">📊 Dashboard</a>
        <?php if ($_SESSION["rol"] === "admin"): ?>
            <a href="wishield.php">📝 Registro de usuarios</a>
            <a href="logs.php">🕓 Logs de acceso</a>
        <?php endif; ?>
        <a href="logout.php">🚪 Cerrar sesión</a>
        <div class="info">Sesión iniciada como <strong><?php echo $_SESSION["nombre"]; ?></strong> (<?php echo $_SESSION["rol"]; ?>)</div>
    <?php endif; ?>
</div>

</body>
</html>
