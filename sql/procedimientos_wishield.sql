
DELIMITER //

CREATE PROCEDURE sp_insertar_usuario (
    IN p_nombre VARCHAR(100),
    IN p_email VARCHAR(100),
    IN p_contraseña VARCHAR(255),
    IN p_rol VARCHAR(50),
    IN p_mac_address VARCHAR(100),
    IN p_ip_address VARCHAR(100),
    IN p_tipo_dispositivo VARCHAR(50),
    IN p_clave_encriptacion VARCHAR(255)
)
BEGIN
    DECLARE uid INT;
    INSERT INTO usuarios (nombre, email, contraseña, rol)
    VALUES (p_nombre, p_email, p_contraseña, p_rol);
    SET uid = LAST_INSERT_ID();
    INSERT INTO Dispositivos (usuario_id, mac_address, ip_address, tipo_dispositivo)
    VALUES (
        uid,
        AES_ENCRYPT(p_mac_address, p_clave_encriptacion),
        AES_ENCRYPT(p_ip_address, p_clave_encriptacion),
        p_tipo_dispositivo
    );
    SELECT uid AS nuevo_usuario_id;
END //

CREATE PROCEDURE sp_total_vulnerabilidades ()
BEGIN
    SELECT tipo_vulnerabilidad, COUNT(*) AS total
    FROM Vulnerabilidades
    GROUP BY tipo_vulnerabilidad;
END //

CREATE PROCEDURE sp_usuarios_por_rol(IN p_rol VARCHAR(50))
BEGIN
    SELECT usuario_id, nombre, email
    FROM usuarios
    WHERE rol = p_rol;
END //

CREATE PROCEDURE sp_total_por_rol()
BEGIN
    SELECT rol, COUNT(*) AS total
    FROM usuarios
    GROUP BY rol;
END //

DELIMITER ;

DELIMITER //

-- Mostrar los logs de acceso por usuario (nombre, email, última conexión)
CREATE PROCEDURE sp_logs_por_usuario ()
BEGIN
    SELECT u.usuario_id, u.nombre, u.email, MAX(l.fecha_hora) AS ultima_conexion
    FROM usuarios u
    LEFT JOIN logs_acceso l ON u.usuario_id = l.usuario_id
    GROUP BY u.usuario_id, u.nombre, u.email
    ORDER BY ultima_conexion DESC;
END //

-- Total de sesiones activas por día (últimos 7 días)
CREATE PROCEDURE sp_actividad_por_fecha ()
BEGIN
    SELECT DATE(timestamp_inicio) AS fecha, COUNT(*) AS sesiones
    FROM Sesiones_Conexion
    WHERE timestamp_inicio >= CURDATE() - INTERVAL 7 DAY
    GROUP BY DATE(timestamp_inicio)
    ORDER BY fecha ASC;
END //

-- Total de dispositivos por tipo (para gráfico de pastel o barras)
CREATE PROCEDURE sp_dispositivos_por_tipo ()
BEGIN
    SELECT tipo_dispositivo, COUNT(*) AS total
    FROM Dispositivos
    GROUP BY tipo_dispositivo
    ORDER BY total DESC;
END //

DELIMITER ;

