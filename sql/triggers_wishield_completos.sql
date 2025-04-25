
DELIMITER //

-- Trigger 1: Logs de acceso
CREATE TRIGGER tr_log_acceso_usuario
AFTER INSERT ON logs_acceso
FOR EACH ROW
BEGIN
    -- Puede extenderse para registrar estado o auditoría
END //

-- Trigger 2: Evitar eliminar admins
CREATE TRIGGER tr_prevent_admin_delete
BEFORE DELETE ON usuarios
FOR EACH ROW
BEGIN
    IF OLD.rol = 'admin' THEN
        SIGNAL SQLSTATE '45000'
        SET MESSAGE_TEXT = '⛔ No se puede eliminar un usuario con rol de administrador.';
    END IF;
END //

-- Trigger 3: Añadir vulnerabilidad automática tras insertar dispositivo
CREATE TRIGGER tr_auto_revisar_vuln
AFTER INSERT ON Dispositivos
FOR EACH ROW
BEGIN
    IF NEW.tipo_dispositivo = 'Smart TV' THEN
        INSERT INTO Vulnerabilidades (dispositivo_id, tipo_vulnerabilidad, severidad, fecha_deteccion)
        VALUES (NEW.dispositivo_id, 'Fuga de datos detectada', 'crítica', CURDATE());
    ELSEIF NEW.tipo_dispositivo = 'Smartphone' THEN
        INSERT INTO Vulnerabilidades (dispositivo_id, tipo_vulnerabilidad, severidad, fecha_deteccion)
        VALUES (NEW.dispositivo_id, 'Intento de acceso no autorizado', 'alta', CURDATE());
    END IF;
END //

-- Trigger 4: Eliminar tokens anteriores antes de insertar uno nuevo
CREATE TRIGGER tr_token_reset_cleanup
BEFORE INSERT ON recuperacion_tokens
FOR EACH ROW
BEGIN
    DELETE FROM recuperacion_tokens
    WHERE usuario_id = NEW.usuario_id;
END //

DELIMITER ;
