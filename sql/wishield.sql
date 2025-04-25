CREATE SCHEMA wishield;

-- Creamos las tablas
CREATE TABLE `usuarios` (
  `usuario_id` int(11) NOT NULL,
  `nombre` varchar(100) NOT NULL,
  `email` varchar(100) NOT NULL,
  `rol` enum('estudiante','invitado','admin') NOT NULL,
  `contraseña` varchar(255) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE `dispositivos` (
  `dispositivo_id` int(11) NOT NULL,
  `usuario_id` int(11) NOT NULL,
  `mac_address` varchar(17) NOT NULL,
  `ip_address` varchar(15) DEFAULT NULL,
  `tipo_dispositivo` varchar(50) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE `eventos_monitorizacion` (
  `evento_id` int(11) NOT NULL,
  `mac_address` varchar(17) NOT NULL,
  `timestamp` datetime NOT NULL,
  `rssi` int(11) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE `vulnerabilidades` (
  `vulnerabilidad_id` int(11) NOT NULL,
  `dispositivo_id` int(11) NOT NULL,
  `tipo_vulnerabilidad` varchar(255) NOT NULL,
  `severidad` enum('baja','media','alta','crítica') NOT NULL,
  `fecha_deteccion` date NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE `logs_acceso` (
  `id` int(11) NOT NULL,
  `usuario_id` int(11) NOT NULL,
  `fecha_hora` datetime NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE `recuperacion_tokens` (
  `id` int(11) NOT NULL,
  `usuario_id` int(11) NOT NULL,
  `token` varchar(255) NOT NULL,
  `fecha_expiracion` datetime NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE `redes` (
  `red_id` int(11) NOT NULL,
  `nombre` varchar(50) NOT NULL,
  `tipo` enum('segura','pública','administrativa') NOT NULL,
  `configuracion` text NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE `sesiones_conexion` (
  `sesion_id` int(11) NOT NULL,
  `dispositivo_id` int(11) NOT NULL,
  `timestamp_inicio` datetime NOT NULL,
  `timestamp_fin` datetime DEFAULT NULL,
  `red` enum('administrativa','estudiantes','invitados') NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE `auditoria` (
  `id` int(11) NOT NULL,
  `usuario_id` int(11) DEFAULT NULL,
  `accion` varchar(255) DEFAULT NULL,
  `fecha` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- Disparadores o Triggers
DELIMITER $$
CREATE TRIGGER `tr_prevent_admin_delete` BEFORE DELETE ON `usuarios` FOR EACH ROW BEGIN
    IF OLD.rol = 'admin' THEN
        SIGNAL SQLSTATE '45000'
        SET MESSAGE_TEXT = '⛔ No se puede eliminar un usuario con rol de administrador.';
    END IF;
END
$$
DELIMITER ;

DELIMITER $$
CREATE TRIGGER `tr_token_reset_cleanup` BEFORE INSERT ON `recuperacion_tokens` FOR EACH ROW BEGIN
    DELETE FROM recuperacion_tokens
    WHERE usuario_id = NEW.usuario_id;
END
$$
DELIMITER ;

DELIMITER $$
CREATE TRIGGER `tr_auto_revisar_vuln` AFTER INSERT ON `dispositivos` FOR EACH ROW BEGIN
    IF NEW.tipo_dispositivo = 'Smart TV' THEN
        INSERT INTO Vulnerabilidades (dispositivo_id, tipo_vulnerabilidad, severidad, fecha_deteccion)
        VALUES (NEW.dispositivo_id, 'Fuga de datos detectada', 'crítica', CURDATE());
    ELSEIF NEW.tipo_dispositivo = 'Smartphone' THEN
        INSERT INTO Vulnerabilidades (dispositivo_id, tipo_vulnerabilidad, severidad, fecha_deteccion)
        VALUES (NEW.dispositivo_id, 'Intento de acceso no autorizado', 'alta', CURDATE());
    END IF;
END
$$
DELIMITER ;

-- Procedimientos
DELIMITER $$
CREATE DEFINER=`root`@`localhost` PROCEDURE `sp_actividad_por_fecha` ()   BEGIN
    SELECT DATE(timestamp_inicio) AS fecha, COUNT(*) AS sesiones
    FROM Sesiones_Conexion
    WHERE timestamp_inicio >= CURDATE() - INTERVAL 7 DAY
    GROUP BY DATE(timestamp_inicio)
    ORDER BY fecha ASC;
END$$

CREATE DEFINER=`root`@`localhost` PROCEDURE `sp_dispositivos_por_tipo` ()   BEGIN
    SELECT tipo_dispositivo, COUNT(*) AS total
    FROM Dispositivos
    GROUP BY tipo_dispositivo
    ORDER BY total DESC;
END$$

CREATE DEFINER=`root`@`localhost` PROCEDURE `sp_insertar_usuario` (IN `p_nombre` VARCHAR(100), IN `p_email` VARCHAR(100), IN `p_contraseña` VARCHAR(255), IN `p_rol` VARCHAR(50), IN `p_mac_address` VARCHAR(100), IN `p_ip_address` VARCHAR(100), IN `p_tipo_dispositivo` VARCHAR(50), IN `p_clave_encriptacion` VARCHAR(255))   BEGIN
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
END$$

CREATE DEFINER=`root`@`localhost` PROCEDURE `sp_logs_por_usuario` ()   BEGIN
    SELECT u.usuario_id, u.nombre, u.email, MAX(l.fecha_hora) AS ultima_conexion
    FROM usuarios u
    LEFT JOIN logs_acceso l ON u.usuario_id = l.usuario_id
    GROUP BY u.usuario_id, u.nombre, u.email
    ORDER BY ultima_conexion DESC;
END$$

CREATE DEFINER=`root`@`localhost` PROCEDURE `sp_sesiones_activas` ()   BEGIN
    SELECT COUNT(*) AS total_activas
    FROM Sesiones_Conexion
    WHERE timestamp_fin IS NULL;
END$$

CREATE DEFINER=`root`@`localhost` PROCEDURE `sp_total_por_rol` ()   BEGIN
    SELECT rol, COUNT(*) AS total
    FROM usuarios
    GROUP BY rol;
END$$

CREATE DEFINER=`root`@`localhost` PROCEDURE `sp_total_vulnerabilidades` ()   BEGIN
    SELECT tipo_vulnerabilidad, COUNT(*) AS total
    FROM Vulnerabilidades
    GROUP BY tipo_vulnerabilidad;
END$$

CREATE DEFINER=`root`@`localhost` PROCEDURE `sp_usuarios_por_rol` (IN `p_rol` VARCHAR(50))   BEGIN
    SELECT usuario_id, nombre, email
    FROM usuarios
    WHERE rol = p_rol;
END$$

DELIMITER ;

-- Volcado de datos para la tabla `redes`
INSERT INTO `redes` (`red_id`, `nombre`, `tipo`, `configuracion`) VALUES
(1, 'Red Estudiantes', 'segura', 'WPA2, filtrado MAC, segmentación VLAN'),
(2, 'Red Invitados', 'pública', 'Portal cautivo, autenticación temporal'),
(3, 'Red Administrativa', 'segura', 'VPN, control de acceso, segmentación'),
(4, 'Red IoT', '', 'Aislada para dispositivos IoT');


SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;


-- Volcado de datos para la tabla `eventos_monitorizacion`
INSERT INTO `eventos_monitorizacion` (`evento_id`, `mac_address`, `timestamp`, `rssi`) VALUES
(1, 'AA:BB:CC:DD:EE:01', '2024-03-18 08:15:00', -45),
(2, 'AA:BB:CC:DD:EE:01', '2024-03-19 08:45:00', -50),
(3, 'AA:BB:CC:DD:EE:02', '2024-03-18 09:45:00', -60),
(4, 'AA:BB:CC:DD:EE:03', '2024-03-18 07:50:00', -50),
(5, 'AA:BB:CC:DD:EE:04', '2024-03-18 11:30:00', -70),
(6, 'AA:BB:CC:DD:EE:05', '2024-03-18 12:15:00', -55),
(7, 'AA:BB:CC:DD:EE:06', '2024-03-19 10:15:00', -65),
(8, 'AA:BB:CC:DD:EE:07', '2024-03-20 07:15:00', -50),
(9, 'AA:BB:CC:DD:EE:08', '2024-03-20 09:15:00', -55),
(10, 'AA:BB:CC:DD:EE:09', '2024-03-20 10:45:00', -60),
(11, 'AA:BB:CC:DD:EE:0A', '2024-03-21 11:15:00', -58);


-- Volcado de datos para la tabla `usuarios`
INSERT INTO `usuarios` (`usuario_id`, `nombre`, `email`, `rol`, `contraseña`) VALUES
(101, 'Kristin Martínez', 'kristin.martínez0@test.com', 'estudiante', '$2y$10$3eCQLPd5NH4NzBN2.OlbNuJYQO0vYvmo64oPKh1bQljzdoZJkr/nS'),
(102, 'Irantzu Romeu', 'irantzu.romeu1@test.com', 'invitado', '$2y$10$rtwGFbmdoicJqYulej.frORScdFRSioPGDGaUXWAWh0OOtauJ0YqW'),
(103, 'Ricard Jaumandreu', 'ricard.jaumandreu2@test.com', 'estudiante', '$2y$10$7oiJ0Hi/HBkto2FADkY1ZOx7uYBVIvKsrE1eXTeK2LrU.TO7QZjmK'),
(104, 'Sara Romeu', 'sara.romeu3@test.com', 'estudiante', '$2y$10$K4/PPE1worXfvYKevOJg6uVrC4jf3SJiAm9RjVtnfsTDVwrJtGrW2'),
(105, 'Rúben Miranda', 'rúben.miranda4@test.com', 'estudiante', '$2y$10$.8qp3k//yO/UxSZnjKdfKOun//o6ttFJr0oPsdZhBpFffQSNSgJlW'),
(106, 'Marivega Irazusta', 'marivega.irazusta5@test.com', 'admin', '$2y$10$PyuIhJKry2v1xr0JRs0xlOh65P0Xm.onk9X480lqf7tjJ76GjJ0rS'),
(107, 'Antonio Orradre', 'antonio.orradre6@test.com', 'admin', '$2y$10$W8K8cEqK3dlEjhmOkH1W3eMG8XcxIv8UkcZoF.g7XT9bmXD8KVIzy'),
(108, 'Antonio Otero', 'antonio.otero7@test.com', 'invitado', '$2y$10$6AIcAS3KczctjXbZbGHl.u8DW0KiXgIbUchMJAixsT/7tI40s8lra'),
(109, 'Ana Becerra', 'ana.becerra8@test.com', 'admin', '$2y$10$BUmNacLOsxR8L1rAT7o4BupKrTiNBbNU6tQTlXYoPwdFJ6WcJe.CS'),
(110, 'MariCarmen Aine', 'maricarmen.aine9@test.com', 'estudiante', '$2y$10$AbtC0fN9EX6dYV6Zja1Mv.S77N1jIvtNTlvTo2zkSCBeBM3ufpW2C'),
(111, 'Nacho Ibañez', 'nacho.ibañez10@test.com', 'invitado', '$2y$10$vNXQnZPuA49dHnbXrZBsxuxM9.YlHx0cVrtdm5t6jmLIYSohdVfGW'),
(112, 'Mercé Botin', 'mercé.botin11@test.com', 'admin', '$2y$10$tlXVnOxsGr.GqpJiU8HEHu3gqBnQH5jMKnsp51YwOUtD/xhdxZgR2'),
(113, 'Irantzu San', 'irantzu.san12@test.com', 'admin', '$2y$10$aO0fqGePeuHqWOIiP.oy0eDmVXW41uNX41TbMYGS6vcKvSUn/C0I.'),
(114, 'Andrea Ennis', 'andrea.ennis13@test.com', 'invitado', '$2y$10$uCkokpdmgobEJTw0VoSXLeEXzNUbZmO1fgDESCcI0LMnZZQRC0lrS'),
(115, 'Mercé Lobo', 'mercé.lobo14@test.com', 'admin', '$2y$10$XfDW4TpYii3TjF4O23HfGuDnIK1P0hym5O0Tlom8X.9gyjXqaGq2e'),
(116, 'Arturo Ortega', 'arturo.ortega15@test.com', 'estudiante', '$2y$10$sPJ2R2Qy0n9bo3RxppX0ueG/4GyubYdDgpYfpBa62Zn7B0oOpqUA6'),
(117, 'Aritz Sánchez', 'aritz.sánchez16@test.com', 'invitado', '$2y$10$5JGRr3GQyswYS.06eOQwkejc4i7u99fR6d3vWcvyklFx3US8awuQa'),
(118, 'Kristin Torres', 'kristin.torres17@test.com', 'admin', '$2y$10$PRPLtL4UPOpVPam6MFGGZ.acO8Xw9wx/1Qt3gnG9Tse3EIJ1O2Me6'),
(119, 'Elena Quijano', 'elena.quijano18@test.com', 'admin', '$2y$10$fm.d58UM2MfyKV5rfLX4VOIdUlxDd89BuiQK.8NTDosM4ohjOPydS'),
(120, 'Ricard Quijano', 'ricard.quijano19@test.com', 'admin', '$2y$10$MpoX0mE6hSBNtIHncBVr8.hbEtwH53SG05O2gGtpihDIhbxqBTiyO'),
(121, 'Aritz Artegoitia', 'aritz.artegoitia20@test.com', 'invitado', '$2y$10$kQKx5pGxNxpy7GM9AMStaOMNvf9tgtaUW3IBr0P72pPkqiTaByNDq'),
(122, 'Diana Lobo', 'diana.lobo21@test.com', 'estudiante', '$2y$10$yUJZdTcgkQEQy5gR12hwVuBOa0wlhAhAiOno4RfLoes76kQigskM6'),
(123, 'Lucía Torres', 'lucía.torres22@test.com', 'estudiante', '$2y$10$q8lrrNqPLz42xIGRSaCxduRe9wHKQ89b.WHTtrtIR0VzSVkUj284G'),
(124, 'Jezabella Irazusta', 'jezabella.irazusta23@test.com', 'admin', '$2y$10$Xdn8PZc9cF6S/5c37BihsOjCj4vzD4KsPGLJRYBtbt29g406gxZo2'),
(125, 'John Casado', 'john.casado24@test.com', 'invitado', '$2y$10$9O73FEZ8nMR6/jIWFoKTjuWjiVrlIOZb4HJ4SJncWoyusSRpyi2HW'),
(126, 'Sergio Nieto', 'sergio.nieto25@test.com', 'admin', '$2y$10$M2XTUIogLUPqrDWI94FAF.JDgEHOe0LLZBT0XEENwhl2zLa2m0Mf.'),
(127, 'Elena García', 'elena.garcía26@test.com', 'admin', '$2y$10$rB0hZInkf.ycUHKMox4XGuYt.jvd8LQOMFt8FevD72uMHIfeVDuwO'),
(128, 'Ben Meldriel', 'ben.meldriel27@test.com', 'admin', '$2y$10$csYguLtQil8K90qVwfYSWeZznsKVNWj4gemzVBUxwbFxsDKJ3d8O2'),
(129, 'Abraham Espinosa', 'abraham.espinosa28@test.com', 'estudiante', '$2y$10$FUoxk3PrcbdUNgiahlayMuaq6LXLgegEBQWkFWtnIADns4T6d6Hxe'),
(130, 'Ben Balada', 'ben.balada29@test.com', 'admin', '$2y$10$x9AEQX6rptKJCpRT/gYrs.VOHtJW/iW2h87M79JKivBYkbduKthcS'),
(131, 'Lucía del Amo', 'lucía.del.amo30@test.com', 'estudiante', '$2y$10$R/lgYyb9F.nfBcQOUd/OTeSeOlHo5sTSkIGSVTxbxpzY3JHLjfGIO'),
(132, 'Kristin del Amo', 'kristin.del.amo31@test.com', 'estudiante', '$2y$10$LKOzzhz.7op48twV4soqBOlDJCBR0sbiapUfjgOIThHHmMW7wNZ/G'),
(133, 'Raquel Toboso', 'raquel.toboso32@test.com', 'invitado', '$2y$10$xszBojyl3dUIC0CfzwtXa.hXpah9d9xcTxTjTIeZI1mYpAjTU032S'),
(134, 'Rúben Raven', 'rúben.raven33@test.com', 'invitado', '$2y$10$ZrOjE4Lnud/H.IqZU1ah6eblgXHbKG6.joj.ikR.9Ja74ERLdWWqi'),
(135, 'Luisa Alonso', 'luisa.alonso34@test.com', 'admin', '$2y$10$cQNKpnyKBNvwQ5BPv/7RWeO6y4AJ5Mpsp518LJXOAhweR2unnZ1NK'),
(136, 'Raúl Quijano', 'raúl.quijano35@test.com', 'estudiante', '$2y$10$iyFBawJSxJji8zoMEIvsDuHCsDBwyqy7eCsOarsRXF4.w0N5DtJ0O'),
(137, 'Elena López', 'elena.lópez36@test.com', 'invitado', '$2y$10$7kf.HB/4CfWecX8vxhbVTODPiwDo85V68UUmnghVYFnjiC69mUxeC'),
(138, 'Diana Becerra', 'diana.becerra37@test.com', 'estudiante', '$2y$10$p130OTxxyw0eQam5UzFtQOJqqKNKM.9d3QD4N151xEClfknIY/mP6'),
(139, 'Ben Romeu', 'ben.romeu38@test.com', 'admin', '$2y$10$/g6lprxTpBcBPBahkMmuaeinAi90mPvSztBgioH9ghPbTfNCqj/AK'),
(140, 'Ana Gómez', 'ana.gómez39@test.com', 'invitado', '$2y$10$IYfte1lgMbri7MLAMEIJbuJMGaGbWghfH03KF0xcagU7PBjGDIKga'),
(141, 'Ana Artegoitia', 'ana.artegoitia40@test.com', 'invitado', '$2y$10$5SR2L.eMyiCLksDQXN3Jr.vYzDBC5ae9tPfpTSvLho8JmBgQFvKB.'),
(142, 'Felix Salomón', 'felix.salomón41@test.com', 'invitado', '$2y$10$nyi/rcSoo6uSWE/PXQs4C.JcTc0ncpeIQMFPGoLnKPeHIzSIJLV.2'),
(143, 'Silvia Casado', 'silvia.casado42@test.com', 'admin', '$2y$10$GY7NuW0.2OzlmfTWu2lLHeVH3P6m5p8VTtsN9QBF9PtiYV9U31vN.'),
(144, 'Silvia Becerra', 'silvia.becerra43@test.com', 'estudiante', '$2y$10$KzZMYzwc2MyZ2vn.71W8AeSnKEA/2eV.Wgr8kmhJi7Hwie9kUwwnu'),
(145, 'Rosa Whateley', 'rosa.whateley44@test.com', 'invitado', '$2y$10$c7zDg53UJxCmoWnDZ9SYTuYOSTdCkRf9jkRhobdQkjU54YaIHBDPq'),
(146, 'Javier Aguiló', 'javier.aguiló45@test.com', 'estudiante', '$2y$10$NW6Y.S0Lht8UB9hPWsYosu7OhyFngVjUEn8N9pb4ILev9pzkHE1A.'),
(147, 'Javier Vega', 'javier.vega46@test.com', 'invitado', '$2y$10$NLNBPYtBgglGg9vMCd2a.uCtlUBWnxaWNHzMc0z1XMZru3EhpZM6K'),
(148, 'Arturo Lobo', 'arturo.lobo47@test.com', 'admin', '$2y$10$N0DGF0CXARFCCtQX5kv5HuwO/dJGOHxAHGUTBEeIiSRBixrb00C4W'),
(149, 'Marivega Gómez', 'marivega.gómez48@test.com', 'invitado', '$2y$10$LnIlx2nInR5UGIx.wJeQmODZ89vnbJYb7ze6R9JYdj01QbeTBxK9K'),
(150, 'Raúl Sánchez', 'raúl.sánchez49@test.com', 'admin', '$2y$10$ZzfMWdXiqNqP193CGcgCCOnTQW5wIquTzkvs3ucbyGiKepU6pjoBG'),
(151, 'John Page', 'john.page50@test.com', 'estudiante', '$2y$10$qoao6NFQCss08/hbM1vWVuw4UgVavpeyU7hiFtoB06ghNM03EYcIG'),
(152, 'Kristin Meldriel', 'kristin.meldriel51@test.com', 'invitado', '$2y$10$/akuRYF7R7A5IpeiJimp9.JFklA.E.LGSVsAi554JubMkBVO/CnSe'),
(153, 'Javier Aine', 'javier.aine52@test.com', 'admin', '$2y$10$.pglr0P37e5IwAiivx43UO48khH2tD24.yXPEU5sWV9BXwqOnulVS'),
(154, 'Raquel Aguiló', 'raquel.aguiló53@test.com', 'estudiante', '$2y$10$JqnWbVFWndQ8Y2vRavR9B.27TlWyTJlNDmMFb.pQb8wKXLjnkfgTG'),
(155, 'Felix Wick', 'felix.wick54@test.com', 'estudiante', '$2y$10$qYFyMc23VODnrMgwfdquYO18bX2C.Z0x2UjoceVz.8QIduDB/id.6'),
(156, 'MariCarmen Meldriel', 'maricarmen.meldriel55@test.com', 'invitado', '$2y$10$oRLHU24uhUStha3u5AgR5Ooqyaqou8FPoSUcOoxtJaP5xWSQXEJqm'),
(157, 'Antonio Pérez', 'antonio.pérez56@test.com', 'estudiante', '$2y$10$Wo0i8YziZqmuxMTwgDoOyOwa5rd8g6G997ny/hVsuCQ7vVBi.SBeC'),
(158, 'Rosa Nieto', 'rosa.nieto57@test.com', 'estudiante', '$2y$10$y9xjDHC20pvpLr.WA3exd.SHkoM0mQE80Qm866FSDbzchl8NWChH.'),
(159, 'Silvia Aguiló', 'silvia.aguiló58@test.com', 'estudiante', '$2y$10$J6Rno1oT4R.st/gJXAmMIuI0BQa85r/wnDtASIYtBhZ3507h/h6YK'),
(160, 'Paula Irazusta', 'paula.irazusta59@test.com', 'estudiante', '$2y$10$A3c1J0PGXvkKjx/mIAYKYet.ckerLFkwuXVL4Yo4U6uJnfd9ccuTi'),
(161, 'Sara Pérez', 'sara.pérez60@test.com', 'admin', '$2y$10$h0aqUXdGv7j5ScuRCM8liutSbLcrZIDHYjVqHSPkjTodRuffDMgym'),
(162, 'Mercé San', 'mercé.san61@test.com', 'invitado', '$2y$10$Gz2qMfM2mu85COXbFAuir.QfxiqpKBK8Dfa3OfsnAYLvzFV/yTaFy'),
(163, 'Sergio Otero', 'sergio.otero62@test.com', 'admin', '$2y$10$DUvZmn6r7x.nXeXPg243Mu4HtxpAmiZo.oSAD1UETMGLJv6RaR.Qi'),
(164, 'Kristin Lobo', 'kristin.lobo63@test.com', 'admin', '$2y$10$200cT6LX544MVvcdlNrkR.1TmvUjzwsI5CaufN6tcPvgtNQsAGVTm'),
(165, 'Felix Becerra', 'felix.becerra64@test.com', 'invitado', '$2y$10$0EDwu9otPBENNfI4pG6zgex8Uzc6yPxs/caeoLa5b/uafsYyb0b5K'),
(166, 'Lucía Torres', 'lucía.torres65@test.com', 'admin', '$2y$10$kfPlLSlfhdO3g0g2dh6QD.7m/PYVQG82bqIpd.8LKSdhm5D6nuotS'),
(167, 'Sara López', 'sara.lópez66@test.com', 'admin', '$2y$10$1qm3XOCWytPlutn3RC2mcePwV0Yqx/60HZGU2zhDugrx.Z83yr7h6'),
(168, 'Arturo Pérez', 'arturo.pérez67@test.com', 'invitado', '$2y$10$qbNSLpUQCPDfsqLcDIephOIjgZG1PCfg8X1kY6SnslO1IbbAgKRpG'),
(169, 'Felix Miranda', 'felix.miranda68@test.com', 'invitado', '$2y$10$Q3op4tofd/CEJqv8NMpYduxW2T5o8xXhmhR8AfnKJ7zO40YKMJ9uO'),
(170, 'Raúl Lobo', 'raúl.lobo69@test.com', 'admin', '$2y$10$nWKRvbNG3yJyDETlrKj4muuOkiBBdT.WMXsEFWuYchV5FFhXm364e'),
(171, 'Ana Toboso', 'ana.toboso70@test.com', 'admin', '$2y$10$Y8TrtgCbGBRedNsVUHkZqOx3VLI2h4rOuE1xwDhl8uastaTC.fuIC'),
(172, 'Javier Irazusta', 'javier.irazusta71@test.com', 'invitado', '$2y$10$PPAEuUxpXcC84oVrQbg14.JdZxiOWZlBPPwQUfByXUzpOyBBhB4ZW'),
(173, 'MariCarmen Aine', 'maricarmen.aine72@test.com', 'admin', '$2y$10$aJLzvQpHiKsnbEwM6EvBlO8TvBerF4Yw.JCUFfgbiiexXrIL9mCIi'),
(174, 'Ben Nieto', 'ben.nieto73@test.com', 'estudiante', '$2y$10$168zQjCIV6EuXV2/XA6O0el1suHVeQuFmeOrQmllLFBBNdAM.Wk.u'),
(175, 'Andrea Limpo', 'andrea.limpo74@test.com', 'invitado', '$2y$10$O6nhbzbspZFPQBkpvYdOkezbONsXslgVUPW6j6y/Qa3aGx3h6o/9G'),
(176, 'Arturo de Oz', 'arturo.de.oz75@test.com', 'invitado', '$2y$10$wQdv6LNNXmtntEM04CzMe.x9eSrMi8I5vIah3xcVwpJ0OhNFDvveW'),
(177, 'Lucía Espinosa', 'lucía.espinosa76@test.com', 'invitado', '$2y$10$AkX3KQj7XqfX6Z8PnnZbe.Uw/cwsraOw9/CEdLFSI.EoFygV9veem'),
(178, 'Paula Boto', 'paula.boto77@test.com', 'invitado', '$2y$10$JN7MmcyqoIvqaOaBHC2FrebqfLrvgCe.xdFV9X2ZIrhCSWDP5pqLm'),
(179, 'Marivega Casado', 'marivega.casado78@test.com', 'admin', '$2y$10$qxJWivsNg3rVB1lUt71VleX6brBaMAqNRSklvyycW5faU.6RMKSDe'),
(180, 'Antonio Otero', 'antonio.otero79@test.com', 'invitado', '$2y$10$ahOfvkNhXm0wzBDNBGQFXORa701/1cKmaE16q0PA1ae0Gbu2Y6gKS'),
(181, 'Abraham Ennis', 'abraham.ennis80@test.com', 'admin', '$2y$10$XCkkl3vUJiDh8U.Mg5iy9.4WgYgE0dJpXlZ.dl/To.DX/e1D5tsb.'),
(182, 'Rosa Aine', 'rosa.aine81@test.com', 'estudiante', '$2y$10$ZPuGAnkbM.plhV1FaFHnCesjaxum00JnFnMpklpHE5PSW6j9c8Tiu'),
(183, 'MariCarmen Alonso', 'maricarmen.alonso82@test.com', 'admin', '$2y$10$ToXbcUfVqITyXmh/FjMmTuSKw4ikFpVCqKBcrAr8DyhhuRSEjCM52'),
(184, 'Rúben Aguiló', 'rúben.aguiló83@test.com', 'admin', '$2y$10$Gi1tfcPj2jsLmjcappOEtum1GPfYNYYi5jSFUpLo8rdgaS8AdO3s2'),
(185, 'Nacho López', 'nacho.lópez84@test.com', 'invitado', '$2y$10$U.0nRoJ3AWZt9rosFzUIEuUGFZFl5MRll6MYxn/bHC2l6pNFFsMo.'),
(186, 'Andrea Meldriel', 'andrea.meldriel85@test.com', 'estudiante', '$2y$10$pdJl8Qid.kpcd3EhAG58neFN6SGiho4QAQnM7PNnkUGUSSzAcmNjW'),
(187, 'Jorge Casado', 'jorge.casado86@test.com', 'admin', '$2y$10$/DFJkbmkJMmbCf.zfkwFUu00t1Mbu1H3cX7F8/.hUl4qUaE2cqogC'),
(188, 'David de Oz', 'david.de.oz87@test.com', 'admin', '$2y$10$T99FYN6tpw0G4NrZAsj/9ucmKZ78xyTNUV/u3A0IdvYlPvTmUj8mK'),
(189, 'David López', 'david.lópez88@test.com', 'invitado', '$2y$10$RJME5TedDNDqlgqHdK6cxeBKxT2oYH.eeYACsZXz246gwltnY/5oW'),
(190, 'Luisa Botin', 'luisa.botin89@test.com', 'admin', '$2y$10$e62cn82cSNjeJ2MXUIvsduYR88RBWp.9qAXk//oSKA/SOIIjQxdPW'),
(191, 'Irantzu Pérez', 'irantzu.pérez90@test.com', 'admin', '$2y$10$sr1TTykRzpKMVGVQVC0yVOP.XK6H9H5PA/QeCdUqx1v6EbDPHgrxO'),
(192, 'Antonio Botin', 'antonio.botin91@test.com', 'admin', '$2y$10$eyBrwU786Fkgu7ttG/cM5ecLFuK1/LUXg5PrbUgR/cHSOkK4.frha'),
(193, 'Diana Torres', 'diana.torres92@test.com', 'estudiante', '$2y$10$tVUhGUpuWQbpFJvaxZs.AepiWIDc78.OKs5KBPhafe6CZ2MOlJLy6'),
(194, 'Paula Lobo', 'paula.lobo93@test.com', 'estudiante', '$2y$10$58SBCJV1PMqPudKUMl4t5OJaG7E/z8OC3PDCwDlE.BRzqnFz.T5iO'),
(195, 'Diana San', 'diana.san94@test.com', 'admin', '$2y$10$TA51USfHHQ9bwLLzUjFChuSqHrn2cX7B.lEdhTFZGrFa2zc.GVP3i'),
(196, 'Diana Quijano', 'diana.quijano95@test.com', 'invitado', '$2y$10$haWUNTmHp4mxOvoPDsOe5eFwHoUrLg4qGEXPeH6bj2h0B/18OGaOK'),
(197, 'Marivega Narciandi', 'marivega.narciandi96@test.com', 'admin', '$2y$10$FS7e7jQ4trF.THPS/HliC.VSYEZJ.lthrtNME5vJpcl9koeQnOFvi'),
(198, 'Ana San', 'ana.san97@test.com', 'estudiante', '$2y$10$as1tVQkCXCozuCRFPf.5tOj1dUJ1MTHr27b6YbhjxRQDtUs5xtfgS'),
(199, 'Felix de Oz', 'felix.de.oz98@test.com', 'admin', '$2y$10$E30ssuqGwu4GTlGpYjVMoOexFE3I3r9BZS0hXuAwj15Ljf2nTkXda'),
(200, 'Jorge Limpo', 'jorge.limpo99@test.com', 'invitado', '$2y$10$FgcQ4u/NRDNDdrX8REQe5ujuZkmxgDDGWFkbGyq8G1FmdeCG/X.O2'),
(501, 'Elvira Luzdivino', 'elvira.luzdivino0@test.com', 'estudiante', '$2y$10$qpVF9lv1kSBHkq3Z.N2D3eMEgVCISp17YzPDJ1YAVsIKDU55ggjmW'),
(502, 'Expiración Japón', 'expiración.japón1@test.com', 'admin', '$2y$10$MytcYLcYs8WrQJUul5b9pO9ltdqTe0fTbg99Of9mxLZey6PeCc2by'),
(503, 'Paz Delano', 'paz.delano2@test.com', 'admin', '$2y$10$UQrRLDjYWXEG1bLJHWMAueuIJ1YrsgUytVaAdWisBkX5TeBtuAK1m'),
(504, 'Jerson Patel', 'jerson.patel3@test.com', 'invitado', '$2y$10$IGPxhfcstEWh2bduyoDH7ebbQVeAdOsIyxJU/GsxFg0RhmVug.mjC'),
(505, 'John Artemisa', 'john.artemisa4@test.com', 'invitado', '$2y$10$EAenwbTk0I17dii78JmzKeUTyx6ydQcAuBZw52JqXcMdJGQFQ44De'),
(506, 'Javier Lioncourt', 'javier.lioncourt5@test.com', 'invitado', '$2y$10$qVORaDbvyUcKUZ3DzNqptenozsTOcKHFBvi2BwfUs4uY3Fa.WWcqS'),
(507, 'Ana Honrado', 'ana.honrado6@test.com', 'invitado', '$2y$10$BY8qx1L/a.YLe79SeQKSeOy5l/hZEhRH8gRJcjXOvBtmiYpiQzZEm'),
(508, 'Bojan de la Paz', 'bojan.de.la.paz7@test.com', 'invitado', '$2y$10$8cyujlGevbuJdZbONccOIOZ55HeNMaIHxZAYqag6dedpWL/3CDB9y'),
(509, 'Eros Amor', 'eros.amor8@test.com', 'invitado', '$2y$10$NbpeciwNU.lniN5H1BxSfOzYvlR4XPvlQYBQOYouKfKCH/LdUbNgC'),
(510, 'Aaron de Cabeza', 'aaron.de.cabeza9@test.com', 'invitado', '$2y$10$Y.n3PwsgaMYjCOTAQ2QQUOPOZEUILEnKsyA1IoqcF6W.LtF8LFFpu'),
(511, 'Elsa Parahoy', 'elsa.parahoy10@test.com', 'invitado', '$2y$10$vufZsw9isyiSUNGvBHF5MOM3eX2yW6RuvIZtIDo9cKTIWYB4ij4oC'),
(512, 'Elvira Oristila', 'elvira.oristila11@test.com', 'estudiante', '$2y$10$2lIL90ig5m7JVxznjKwWIO9jkJJ7ScyeMyPygG68fsj.56IvQdaAe'),
(513, 'Fermin Parahoy', 'fermin.parahoy12@test.com', 'admin', '$2y$10$8Mt9eyDDPbE9nSCF/X.o0OaEA309C.ag5DKo/iU9p.IbwrtyDx56S'),
(514, 'Hercules Honrado', 'hercules.honrado13@test.com', 'invitado', '$2y$10$J2Tay92RbCMlT8bjSHEyEecojVZOCPP9lNUbdFH/HUFMuOoPax4..'),
(515, 'Alyona Piedrasantas', 'alyona.piedrasantas14@test.com', 'invitado', '$2y$10$9DIurGiSYW5PezjFV8C3tuzbtlICWUfvp/SHXGja6KT5h9H6numO.'),
(516, 'Fermin Cremento', 'fermin.cremento15@test.com', 'invitado', '$2y$10$GfykrqYwtw.yOdiULfpJL.l3cnPi8i4KtxFhWMU8QMvOsWUZ2CE6a'),
(517, 'Arsenio de la Marina', 'arsenio.de.la.marina16@test.com', 'admin', '$2y$10$X/lv0A5dErToY3b9XgpJQe5CVoQZcvp2iKziniukxvUQfPT/7n3KO'),
(518, 'Arnulfo Sandro', 'arnulfo.sandro17@test.com', 'invitado', '$2y$10$Zam227G2hT8VzGZGNuFVmOCAU2rsGaf4.Nh5UKRMPVdRGOriESe72'),
(519, 'Bojan Nito', 'bojan.nito18@test.com', 'invitado', '$2y$10$J2qyFdWu7DnB2WxLmIIG2.p8QrPonZjwc6CcE8lPQQ/yoqElIMxxm'),
(520, 'Cipriniano Busado', 'cipriniano.busado19@test.com', 'estudiante', '$2y$10$AcCS80Z3yNGwgs3Fs0wSweArJdADFmxT7q6T9uAS71uClgFcIbFI.'),
(521, 'Uriel Bojan', 'uriel.bojan20@test.com', 'estudiante', '$2y$10$XDY/UeUhfmdWIRreV/RxM.e1LeJbUBRqAHoIDe5kmrHiX.aqTcxDy'),
(522, 'Ricard Martínez', 'ricard.martínez21@test.com', 'invitado', '$2y$10$fVeNZvCL..W7fydZFI.E5uEuOBie05NRET6WngC4IrGcsKUjTbQk6'),
(523, 'Estanislada Verdugo', 'estanislada.verdugo22@test.com', 'admin', '$2y$10$H.Vv7bQR6j7bd3kS3ikw.echclcEwVPBU2znLlyer8ImOGLOrY7G2'),
(524, 'Renee Alegre', 'renee.alegre23@test.com', 'invitado', '$2y$10$V4sS/zKlAv5EQiEdcLsKTOjqZzb0hUa5VQlImQ6M6OT58aoiQtM8O'),
(525, 'Marcial Altagracia', 'marcial.altagracia24@test.com', 'invitado', '$2y$10$BO85qkvF.xB4F0.5CbTzgum7hXrWey2s/31yyoBxR40JPFh8CqEIu'),
(526, 'Penitencia Ladrón', 'penitencia.ladrón25@test.com', 'invitado', '$2y$10$Ggf0d8ZiwHf2EEOK2R.A7ekUzkxUmRIfN/fGp/8BfeMLDq3p..8fS'),
(527, 'Elba Jurado', 'elba.jurado26@test.com', 'estudiante', '$2y$10$KBoijEMYmqh5kWmqk9RkCeyxEZfTdcIsICYwcbjLqyRPmCeIlGqIm'),
(528, 'Carmen Mogollón', 'carmen.mogollón27@test.com', 'admin', '$2y$10$6eHY/UfqPBxM99U4XKv4uuN8XO3bU/V0TVcr5VMjtLcLOpCWsLag.'),
(529, 'Serge Diogenes', 'serge.diogenes28@test.com', 'estudiante', '$2y$10$OZ4.Ds9vPeoyifXYkLMwVuESdHDpzx72RouUexqboWoUI.OY2H/uC'),
(530, 'Nick Luzdivino', 'nick.luzdivino29@test.com', 'invitado', '$2y$10$i0C5Wh61tErwlXPNaOK6mepMCVWB2E67grXu3P9cuTRUSFWu.QBj2'),
(531, 'Brais Salido', 'brais.salido30@test.com', 'invitado', '$2y$10$b8doqCRSyfj0eqvxdyYoH.lh5SWrkiS0SVfqp1vokNPagnlL5vsdK'),
(532, 'Tesifonte Mogollón', 'tesifonte.mogollón31@test.com', 'estudiante', '$2y$10$4s4Xg8uDIphV8tiYEnnD1uppmKdGJBWPKgduv6Ut5VVG6Ld6jIXfe'),
(533, 'Ben Gandula', 'ben.gandula32@test.com', 'estudiante', '$2y$10$59SKzsjdFow9WoIRZg9/Vey3BLp2n43uPt/cdH2AA3B0lFlh94dxa'),
(534, 'Dolores Estanislada', 'dolores.estanislada33@test.com', 'admin', '$2y$10$.I0a6Sl2ExB3UHFzMZKxVOu/4iJieFQchOx6OxUuNRWOtJkCEVOAm'),
(535, 'Marina Expiración', 'marina.expiración34@test.com', 'estudiante', '$2y$10$fZe9rHI3eK/qf8n/aF3ASeWAv4h6N0R7kyaKT1fyM/dJW7gAcB0XO'),
(536, 'Elvira Valentino', 'elvira.valentino35@test.com', 'estudiante', '$2y$10$S0ual2V9fBZkS9qWZq2dQedtuxWjvi3ZKQl/5jByq0IiVCZVaA0rG'),
(537, 'Penitencia Bojan', 'penitencia.bojan36@test.com', 'admin', '$2y$10$YcRWrfG30kNNwkM.DJnaEOJ5H1/Mua4proapxKNln4NXYRhYtvrn6'),
(538, 'Iker Cipriniano', 'iker.cipriniano37@test.com', 'estudiante', '$2y$10$O4iBAupH/TPMZUHWB6B3weXU24qMnXDngxteZk4cmMLJ7WG5zmYWS'),
(539, 'Enzo Burgundófora', 'enzo.burgundófora38@test.com', 'admin', '$2y$10$/6jVlXMr.knYwCvlpC/kCuDtTHZUXWt02YMYLOOG8SL4OxVSOfsLW'),
(540, 'Armando Iluminado', 'armando.iluminado39@test.com', 'admin', '$2y$10$eXBB6RoUj/ojfbJ2.7BK4eEZCnWpJOqx8LatlAp6UvMgR9ygfQJtW'),
(541, 'Xavier Bonifacio', 'xavier.bonifacio40@test.com', 'invitado', '$2y$10$mdlFnm9F5/7OUN/lEzqhIefzFrKRtV.1oIpG5469aXNyoQOysNk.i'),
(542, 'Blanca Lioncourt', 'blanca.lioncourt41@test.com', 'admin', '$2y$10$js4hHp.W85SzwIeMmC/5p.T.4JtdlChNeQ9Qv61rgDxA141QiLyIi'),
(543, 'Isabel Kermit', 'isabel.kermit42@test.com', 'estudiante', '$2y$10$S0r9J/rA5cjL0w/Mukjj9OTUA7bh194l5MtgDRQqncCwr2Ag26tES'),
(544, 'Patxi Oristila', 'patxi.oristila43@test.com', 'estudiante', '$2y$10$2tyQrP92Fm8sCGpm6CI0OeiuPxb3jCx95otZNQiwCOXLM0STM63cW'),
(545, 'Valentina Botelli', 'valentina.botelli44@test.com', 'admin', '$2y$10$9OxTxUyiWBj8ZHWzyWIptOGEv2SAmCEMHjqfmp7RKYAgOWBZ72Cxu'),
(546, 'Diana Sánchez', 'diana.sánchez45@test.com', 'estudiante', '$2y$10$WfKKuuF7XNpeTRK8oVIYfOBE4CaYGSxO4dAchXClDRCg65rVm38m6'),
(547, 'MariCarmen de Covadonga', 'maricarmen.de.covadonga46@test.com', 'invitado', '$2y$10$N6e2AJr8qHVqA9uSeftLte2Y3IbNcNAKvOLvOIn/6JEcRupGFaVEW'),
(548, 'Mark Segismundo', 'mark.segismundo47@test.com', 'admin', '$2y$10$sWdV6gElfVuadlPp9SOQmO9J5Sc56RZHIQcvs.Z4K.p0COKp/oLcO'),
(549, 'Marcos Bonachera', 'marcos.bonachera48@test.com', 'admin', '$2y$10$w6KrW19TDcezWBLAhkIx7.BsAj8zlPlLbsJG.xGlbiSTr/Fzh3BUC'),
(550, 'Ezequiel Jetson', 'ezequiel.jetson49@test.com', 'estudiante', '$2y$10$KfoMa6yy4crVZLJTqMp6aO5vCdPag4IQ68QbOsEXegLh31ZJl3YuW'),
(551, 'Diana Salido', 'diana.salido50@test.com', 'estudiante', '$2y$10$W6TOCdv9T7D3hvp56YIpv./7UD0m8nNhlUPgz.nLPVfY7am5GLRMC'),
(552, 'Nick Patel', 'nick.patel51@test.com', 'admin', '$2y$10$OTdZBuZMrVRXDI0ozXs.U.MF3HYPgSJlbdDcoYMmDGofvXfhwyBsy'),
(553, 'Diego Kermit', 'diego.kermit52@test.com', 'invitado', '$2y$10$EFHIuU/nXxR2pqvT6l9eV.iIqCLZNCklJMGyDdPLcSnVJlFyVbCpW'),
(554, 'Leo Fina', 'leo.fina53@test.com', 'invitado', '$2y$10$s5RXzytyUZFX.cqwyA2mpuYAa6hpdKq8ekYUm2Y1A2z3cTLNFWlxu'),
(555, 'Diego Armandez', 'diego.armandez54@test.com', 'invitado', '$2y$10$47QmX/somG3BCcJuVQ53augO.bOhHkyyKqk0iCpTwqUrorBcVrHpe'),
(556, 'Xavier Irantzu', 'xavier.irantzu55@test.com', 'invitado', '$2y$10$peD67ex4yso2JgvZi3b9MOPnaDelogvFnC01x6474xRQ2jqKP82i6'),
(557, 'Fulgencio Piedrasantas', 'fulgencio.piedrasantas56@test.com', 'invitado', '$2y$10$p5C32OdO/FU43t0UyFHu1eSvVq43iPPPOqpeGQ4uDAtXepco16vPu'),
(558, 'Antonio Miles', 'antonio.miles57@test.com', 'admin', '$2y$10$1zRQzbCdCPRZMuY1AjDP3.X8lJbgswy7/emdIA9JCdcklYiqwddCq'),
(559, 'Marina Aritz', 'marina.aritz58@test.com', 'estudiante', '$2y$10$6.g0FnLF4v58/2xY2ryWp.QQZ0rbD5lNkfV3wwXNaIPdqO33geT8i'),
(560, 'Cipriniano Silvo', 'cipriniano.silvo59@test.com', 'invitado', '$2y$10$D5WLkmaiWd5fHEP5wAu9/uXhiySImYCB8snBvByLslQE1ofM22ODu'),
(561, 'Marivega Marciana', 'marivega.marciana60@test.com', 'estudiante', '$2y$10$cyJxSdZGqK0JKxrcGSD2Wu6Xc3u46.3/AnHKzKL.NxgwJQ4fsqXd2'),
(562, 'Elvira de la Paz', 'elvira.de.la.paz61@test.com', 'admin', '$2y$10$srUeVRH.QCYHg7pwkEYSAOYJ7BzUyxhCGLO.U/f6sEINlWHYx8E1y'),
(563, 'Mark Esario', 'mark.esario62@test.com', 'estudiante', '$2y$10$GCKT62lvNchAWp2a/oGbk.ZMAEzMkXhY187A1sD3ZV.7HSMqrRm6q'),
(564, 'Protasio Diosnelio', 'protasio.diosnelio63@test.com', 'invitado', '$2y$10$CzPU1rzcJpuihNlHeQ.eJeCk4kEIzCcggLKM04KVXQJY2dNDepes6'),
(565, 'Marivega Tresado', 'marivega.tresado64@test.com', 'admin', '$2y$10$BTl2nyXgj1PFbjgyViMLKOogaJCkDjBWWetD0u7h1m3FrM23E9HKu'),
(566, 'Raúl Masdeu', 'raúl.masdeu65@test.com', 'invitado', '$2y$10$DDvkD7L7PpOUWYczBVs8x.WRIkKPMqjOJbjRWweUIzi7AbpCYb0dS'),
(567, 'Sergio Elsa', 'sergio.elsa66@test.com', 'admin', '$2y$10$qVS2JAzm1MKodL98ZdorPO/yVeCky0qJh9YmJoJiQdG5lEDdZumZ.'),
(568, 'Bonifacio Alcoholado', 'bonifacio.alcoholado67@test.com', 'admin', '$2y$10$SoRgAjGiLKWBJKKMQNUbBO6egJ0XPUWctk40qTlKsWsryLGI8Vj9a'),
(569, 'Valentina Pérez', 'valentina.pérez68@test.com', 'estudiante', '$2y$10$OZX444zNiqDHY6O8yaU4AO40T11oQN7/WoSRGwPUE5C4ZaJuaVqlC'),
(570, 'Iker Arsenio', 'iker.arsenio69@test.com', 'invitado', '$2y$10$YTvoeJy1dalw2/nLN7Kq6.WJ3S26i4YqPHnfCQEtxHoJx/NRfp9GG'),
(571, 'Elsa Gil', 'elsa.gil70@test.com', 'admin', '$2y$10$yfRqWJChEkqvV/u2c0jqmObth2OuPkrklsiYnlM.03OScaGWXqlui'),
(572, 'Marivega Estanislada', 'marivega.estanislada71@test.com', 'admin', '$2y$10$At69gqIlfYKv9Pwb30l2NumJBWghmCiRufzR1RP8gHz3PlLPO6zBm'),
(573, 'Raquel Oristila', 'raquel.oristila72@test.com', 'estudiante', '$2y$10$PD1A4fHL8BWSdE4ZYmUaBeFu7eKzgAxU2knZxSg8OSx4vEyMtITX.'),
(574, 'Dolores Delano', 'dolores.delano73@test.com', 'estudiante', '$2y$10$bOYSYIJEVOtUAxrg/Z5L0OBtrfWnhwUqTBOaY67wqZqm1FyVry.Fa'),
(575, 'Irantzu Diogenes', 'irantzu.diogenes74@test.com', 'estudiante', '$2y$10$4YDvl6VARxoccwMWoj9aUuQ7aQg13aQzmr.8jukUaAgVyT.6gZoxi'),
(576, 'Jezabella del Carmen', 'jezabella.del.carmen75@test.com', 'admin', '$2y$10$VyIUVwgFqFBVAz1.H/beRe0Uny8LAx6n8foYGnAylG.MqMxZB2CQ.'),
(577, 'Otto Parahoy', 'otto.parahoy76@test.com', 'estudiante', '$2y$10$MoIn4gzhzCSxtLO0YvLCheZi7VaL.eISEwujteoh6vKIvii1zAhtO'),
(583, 'Isabel Cortada', 'isabel.cortada77@test.com', 'admin', '$2y$10$cabcs5GxKQenYKAVlSy0/e2xHRuIr1/EwQIpkJhl/usj9FzQSFgMi'),
(588, 'Elba Diosnelio', 'elba.diosnelio78@test.com', 'estudiante', '$2y$10$ufiZophh28aSxUPFLcvNIeQC.6R6mfBjdMMtuZd3g5bh5lG5JIE/m'),
(594, 'Nacho Sánchez', 'nacho.sánchez79@test.com', 'invitado', '$2y$10$VYxX9tBWMaax77sEF/rkjuIAxUEs3.mqBl/ceqyA5yL/CLjEU0zE.'),
(599, 'Miles Martínez', 'miles.martínez80@test.com', 'invitado', '$2y$10$zHvkv9HuVAHElWRstpFY1O6pvSOpn9kAUJIAcSXwM0C6RDHlZDrcm'),
(604, 'Nacho Pieplano', 'nacho.pieplano81@test.com', 'invitado', '$2y$10$UTkVF1bQPpSVEOdoWs79V.k0Iig/7A9Pb1uU.YVwtdfojagubrbim'),
(609, 'Renata Campofrío', 'renata.campofrío82@test.com', 'admin', '$2y$10$YobbGaBe4ie.8oa2wQKo2e058mwBR7vynpYUqaz3jE4P7J5tfr/GG'),
(614, 'Silvia Diogenes', 'silvia.diogenes83@test.com', 'admin', '$2y$10$NriYID2MrkggCu0UHw5JnO3KuqAoLSnF1/FdKgknfS1oJHYBOD7Sq'),
(620, 'Nick Irantzu', 'nick.irantzu84@test.com', 'admin', '$2y$10$s5j8SgvBtVqju677SjA9TOEmQGCfFcQaX854U9ziCZHW239YCeyYa'),
(625, 'Ruperta Segismundo', 'ruperta.segismundo85@test.com', 'invitado', '$2y$10$GrcMfH6G0PnB31DOFV2ypuPooQyic0/aGJ77uVe4AyDxXATfy.Byi'),
(630, 'Iluminado Parahoy', 'iluminado.parahoy86@test.com', 'estudiante', '$2y$10$dWmmqUYYpCZD2F7GY4HIG.tWOWl3rKv4Mv7QJamnM7RuPKMcoKszS'),
(635, 'Pantaleona de la Marina', 'pantaleona.de.la.marina87@test.com', 'admin', '$2y$10$RMXOd6cSV5htAfNP7LQ/n.pUHb7DRETGCaBASZUMFD.XzXB9dENQG'),
(641, 'Sandro Cremento', 'sandro.cremento88@test.com', 'admin', '$2y$10$MsJ5rqjY3vBp2Gq31F25nONQ98mXfYfqD1gkiKMPKJ7H7S3Pgsd9S'),
(646, 'Arsenio Arsenio', 'arsenio.arsenio89@test.com', 'invitado', '$2y$10$Bt7/WVHA9CcL/Xengq13JenfRCNUBv5rTHhm3gzJV8phLA/Orn2jy'),
(649, 'Miles de Barriga', 'miles.de.barriga90@test.com', 'estudiante', '$2y$10$gf4d77GYRvc1at7yPh/YP.QDcXvIsVD4AMK9JFSOu3bzE8V0mp56i'),
(654, 'Uriel Silvo', 'uriel.silvo91@test.com', 'invitado', '$2y$10$8LcxzGF1rW8iHzgQvhWesO7SR6MnsabL58DllADG6aw07y15xfzb2'),
(659, 'Duncan Vergassola', 'duncan.vergassola92@test.com', 'estudiante', '$2y$10$Ngf1cxt3i9m/DcI.N8VZOuOFypLDipgHPbLbdTgwELD4ECqNMyaYy'),
(663, 'Ladislao Marciana', 'ladislao.marciana93@test.com', 'admin', '$2y$10$9hYzXwd8hVlAPuSZlNnjfO/GWT8kmqotHdBHIyxwVO/2JnV3PiRD6'),
(668, 'Uriel Ruiz', 'uriel.ruiz94@test.com', 'estudiante', '$2y$10$aZQNymxyrdKJ7GtQy.L1eu.27Dbi1t1hjg2J5ti.wbSa8/IYGvinC'),
(674, 'Anne Pantaleón', 'anne.pantaleón95@test.com', 'estudiante', '$2y$10$pS7302szZC2fhuV//4MH1unmyWMg0WKwMwIQBLypopZ46AhvnuCEe'),
(679, 'Zigor Hierónides', 'zigor.hierónides96@test.com', 'admin', '$2y$10$co04LB6e1Z6lPLuQkHvp0OR20Y09ynj1OPIaQfxtr6i0XvNsbGGrS'),
(685, 'Drac Escolástico', 'drac.escolástico97@test.com', 'admin', '$2y$10$07KzaGWQtx1OxdEWD0jhW.RuuY6CSrwlrBK.InuY3bb9T0Np77Jle'),
(690, 'Ladislao Elso', 'ladislao.elso98@test.com', 'invitado', '$2y$10$ATeZc6g7im1b5Gw.v6XfJ.cH.KMet5fRTBUBtKiNiZ2Wl6DUuXeHy'),
(695, 'Brais Arnulfo', 'brais.arnulfo99@test.com', 'admin', '$2y$10$Dkh.SF21tIxUDjEYxOojyuxKXien7nc9ZZXWo4xF.yl1t/lq/X59i'),
(701, 'Blanca Diogenes', 'blanca.diogenes100@test.com', 'invitado', '$2y$10$UEfUuvJMxtbRBr.glwVQhOLeGuHN.b1sm4ktlNiy9cvdjJw2zRbYO'),
(706, 'Marina Ruiz', 'marina.ruiz101@test.com', 'invitado', '$2y$10$t6oqZ.iI.m5YzfByZvqdquYLymZjudKej7zhwurfdScYKREVCzlt.'),
(711, 'Jano, Elian Bojan', 'jano,.elian.bojan102@test.com', 'invitado', '$2y$10$iFLbHoLa6gWYJUZ/I6XfIuZt1iUmmC14rfVYryedKRJX7q7GDpEjq'),
(716, 'Montse Campofrío', 'montse.campofrío103@test.com', 'estudiante', '$2y$10$qIutGGRXcEjSf/kzAWjlT.ouIKEcFXZTFck.ct0qI3GDMAA2Cqh.y'),
(721, 'Protasio Marciana', 'protasio.marciana104@test.com', 'invitado', '$2y$10$rBQpJ.d4oM5kgCk.z0KEBufQVJ5AjDrDh7nFo1nsoyEH2DeCdXyWy'),
(726, 'Fulgencio Silvo', 'fulgencio.silvo105@test.com', 'invitado', '$2y$10$beEfh5884/PijGd3vnLN5O4o2z0nvI/tbBdDs0Y8gOckeoShwDWR6'),
(731, 'Marina Leona', 'marina.leona106@test.com', 'estudiante', '$2y$10$KCKnRs/th5jJcibjBV37L.UFsZsNMfrBAJQewRBlc1b84sSP45TIu'),
(736, 'Nacho Bonifacio', 'nacho.bonifacio107@test.com', 'estudiante', '$2y$10$8yJzrdHiZp.VRrGeX95hvOYMUe9i0gQf/MWQGFSyOyoXi9aJ1j0eO'),
(742, 'Marc Osario', 'marc.osario108@test.com', 'invitado', '$2y$10$2CdsmL2UzwPflvVJTBpv5.mdJFsXb4yC159tnAW8KWApQpBh9nC/6'),
(747, 'Yorinda Digna', 'yorinda.digna109@test.com', 'admin', '$2y$10$5mMKV5SKJCVQB3QzGOJep.uYUq.W5mK4KWVk2PJiEuR13UlozaGTa'),
(752, 'Ana Elsa', 'ana.elsa110@test.com', 'admin', '$2y$10$.uQRYH1lBa.XtRSg3hlLhu4J73Si/cGPsxXWmAfzq2XGgYzVy.Z8G'),
(755, 'Yorinda Pieplano', 'yorinda.pieplano111@test.com', 'invitado', '$2y$10$n8eZUGwhROXWpC/5Bs0qp.uNSHLMBNTCpGHmcDdH42yqiTMIbRRtW'),
(759, 'Patxi Jetson', 'patxi.jetson112@test.com', 'invitado', '$2y$10$YsEer0HAD5mtpYF1kIf7H.eB5vA3LCq1sIBTXJunwSbd2TY9JdB..'),
(764, 'Otto Gol', 'otto.gol113@test.com', 'invitado', '$2y$10$R3wXaBP5PHP6eFW2fe4nUuFejs1IYGeWwbe.Z6lpr4phvu8BcvwrO'),
(769, 'Estanislada Diogenes', 'estanislada.diogenes114@test.com', 'invitado', '$2y$10$xLp0HgM3szsWrbDQMuuHSOxoya39r.rPGoL4n0y.NmxUvqhUyucQa'),
(775, 'Abba Diosnelio', 'abba.diosnelio115@test.com', 'estudiante', '$2y$10$lKuQ9ufNnUoV6DHrZhtKKeaOj2v2rbkj7qZ7XGyzfsU9vPFq9MauC'),
(780, 'Brais Elba', 'brais.elba116@test.com', 'invitado', '$2y$10$31xVn6yImsPSPjKJ0Bnbn.UBaJ5DSC2Vu4JS/rtghb/9JmR0cRwv2'),
(785, 'Enzo de la Penitencia', 'enzo.de.la.penitencia117@test.com', 'estudiante', '$2y$10$fc1nfr8LaORfIUt9g.sGLudhYXgo4YLTcY3caxGB6MAvsWrFZ1wp.'),
(791, 'Arsenio Calavera', 'arsenio.calavera118@test.com', 'admin', '$2y$10$v0euBWFNvZr6FMcHbAt8h.DiRuexIzpEcnHsXpUtpttFXjij7A1PS'),
(796, 'Argi Diosnelio', 'argi.diosnelio119@test.com', 'admin', '$2y$10$TLIMuzf/S75Dd.E8nna7vu1BzCo2xuTeUvOxJYup7UQEt4xmFyHcu'),
(801, 'Valentina Armandez', 'valentina.armandez120@test.com', 'estudiante', '$2y$10$AlFyEhqz42jhXH5HxPmnou1Jjw9oV84Yn/q09kS6xTTyaxubwbx7m'),
(806, 'Froilana Elba', 'froilana.elba121@test.com', 'admin', '$2y$10$zc20oLYNoKEilbMRFf/5gO0PX5xCDlcCHR.vETdu1qGsLtpKpF4iS'),
(812, 'Diego Fina', 'diego.fina122@test.com', 'admin', '$2y$10$MRx1HfFI/8vXAJ45ZD76SuiPS2FT4BA4suFKSXNO2HrO2.3qRofiO'),
(817, 'Arturo Mento', 'arturo.mento123@test.com', 'estudiante', '$2y$10$cKCo6JB2syuZzXsj11eUHeJNsCLNPJXfCn3Jr5986Fv0qzmo2Xysa'),
(822, 'Rosa Estanislada', 'rosa.estanislada124@test.com', 'admin', '$2y$10$swJoGqDDCpFmDhZlWK71ju6Shth65bKvORCPCWuUJEMMLq7UlpWaO'),
(827, 'Luisa Busado', 'luisa.busado125@test.com', 'admin', '$2y$10$3Dlb3yATyU5CrOa/ozW6JOVdFlsSlIElKWka6N3HjCj.AZqyOqY2.'),
(833, 'Pedro Masdeu', 'pedro.masdeu126@test.com', 'invitado', '$2y$10$1tC1ZNXom/vugpVhb0bIl.a7DKSPl9HBfPi2Gf2hATP8sCGb2zOlS'),
(838, 'Thais Sandro', 'thais.sandro127@test.com', 'estudiante', '$2y$10$qjvUyqKQvVHyOx.2AqAs/ueKKtfsxKiRwGbOJ1K8uj7s0lB5mBsuW'),
(844, 'Mercé Artemisa', 'mercé.artemisa128@test.com', 'invitado', '$2y$10$hUtla5AHj3KixPecn2asxea0sqpK1kOkh.b8EwFyqxVFSv6otCFd6'),
(849, 'Obdulia Arnulfo', 'obdulia.arnulfo129@test.com', 'admin', '$2y$10$QJbyTXRWu5CgrxeX0xgzyO098AJihELPUrW4yXcCOrN3Yphd8/VcK'),
(854, 'Burgundófora Estanislada', 'burgundófora.estanislada130@test.com', 'admin', '$2y$10$gv07VJowbguBZZ7tzUF1Keeitg6TNsDHQAsdptgSrBkVYZhCpUeu6'),
(859, 'Brais Protasio', 'brais.protasio131@test.com', 'estudiante', '$2y$10$.hp3LtErzt/QKslsKIX1pe4eksuwE2KhHR93LQcqIxqR1vonYLZ/C'),
(862, 'Abril Segismundo', 'abril.segismundo132@test.com', 'invitado', '$2y$10$hfEvaP00SVxOLoQXyMSMtuZNwpAMkiNzXjF4NF.wdZNDKx0itYzKC'),
(866, 'Vanesa de la Paz', 'vanesa.de.la.paz133@test.com', 'estudiante', '$2y$10$UFh681k3jdSzGtB4mphmg.pMDRe8gFnpz7flFyeZTRKAgW7GCqu82'),
(871, 'Segismundo Irantzu', 'segismundo.irantzu134@test.com', 'admin', '$2y$10$o7j6.zVTZQGX6RFeda1foupD/4.SC8hcG0zoqWdeGJ/xhim4nY/dC'),
(875, 'Sergio Busado', 'sergio.busado135@test.com', 'estudiante', '$2y$10$Xi9PqJpGg13QOPrJDCKAp.4AnN3a8v4dFZPhCZCFSIZiJKk2Gr4wC'),
(878, 'Nacho Jetson', 'nacho.jetson136@test.com', 'estudiante', '$2y$10$WaxsE/XOlGHA2m3miFPnwO9S7505t6TS1ImCTxXygOQJknjIzCCPq'),
(883, 'Pantaleona Masdeu', 'pantaleona.masdeu137@test.com', 'invitado', '$2y$10$gU6D2y4SxdpF67PNL2nL7O/12iFh5SIa2aZ4yQ22eT6vrFFL401d6'),
(888, 'David Alegre', 'david.alegre138@test.com', 'admin', '$2y$10$6I0VgxKTLasnaFQ9jZ5lL.sg/uzQt9/z0bJK2FSVQ5G89ASBvNWP2'),
(894, 'Lucía Gandula', 'lucía.gandula139@test.com', 'estudiante', '$2y$10$NBy6p1Eoa.Qfhn6Q5mqoHu8Z/Fs0lF33fYFYtd2CBzzH29WpJoq8.'),
(899, 'Argi Japón', 'argi.japón140@test.com', 'estudiante', '$2y$10$4TCYSegf34rl8Mm0jOqZXu3Q95ep5.yfgdY2RNfq3gWgQ4AaLBy.2'),
(904, 'Hercules Arnulfo', 'hercules.arnulfo141@test.com', 'estudiante', '$2y$10$y3/iUzguUUEQOjlqwqPzL.6Xz1Z/nr38KeCU5pVsbMFiE8LP.4TA2'),
(910, 'Eros Elsa', 'eros.elsa142@test.com', 'invitado', '$2y$10$uUF8/Vy2PoMNWJZNiIp46.yJ6TRQokz.mSeiVNiX4XiNSfs11h1ja'),
(915, 'Obdulia Bonachera', 'obdulia.bonachera143@test.com', 'admin', '$2y$10$iY2Y9pkAaPStzuI2jzqHduNdUnNeIJAT2YG7qXTmC5b.AAge5Y6CK'),
(920, 'Eire Sánchez', 'eire.sánchez144@test.com', 'estudiante', '$2y$10$mtR0BuYavADc1JMu8ssa6.u3Gf/c8NNZxijXI0BWDdYT4H27f2pR6'),
(926, 'Sergio Flores', 'sergio.flores145@test.com', 'admin', '$2y$10$HHbEEoWwvSblW3FsHv2eB.vBCZ27LKZutbiojMAeLx48QpUb6KPH2'),
(932, 'Nick Yorinda', 'nick.yorinda146@test.com', 'invitado', '$2y$10$hTz6feGfafDuLhzo1l3TluDHAwy1ISFHl8/3Wcviji7ya3F1L90TW'),
(936, 'MariCarmen Alcoholado', 'maricarmen.alcoholado147@test.com', 'estudiante', '$2y$10$vPqXeByJdp6dhdNRzOCTk.L4ZCP8ATtR3I0TXOc6k5jt2f3USytm2'),
(941, 'Marc Cremento', 'marc.cremento148@test.com', 'invitado', '$2y$10$BnjtdkZGmsv2XWvkYFPU1e8RjvHVhAuEp2KLqV/Ae5GNsxem28c1m'),
(946, 'Yorinda de la Vega', 'yorinda.de.la.vega149@test.com', 'invitado', '$2y$10$IqHmo0.Rvaev5kdHDm7XDOuJaqO3VHKrDqL5cpw5mib6kNnuWgMu.'),
(951, 'Luzdivino López', 'luzdivino.lópez150@test.com', 'estudiante', '$2y$10$5iYt8RcxYHhvFaDHxdWN0u6.Ui0FVO2oS4HiYGhN4xNHnAaMLboz6'),
(952, 'Elso Protasio', 'elso.protasio0@test.com', 'invitado', '$2y$10$c9AIWPnQsmSyu/.NMpz3Lee46Cq0XDC/qLNeSnWnFQrGZv5kIX4nq'),
(953, 'Laia Piedrasantas', 'laia.piedrasantas151@test.com', 'estudiante', '$2y$10$5AmLeiw1qsjgJOUuFA39WeL1fMstcxhyWbR3H5ktNuktGiBjLplwu'),
(954, 'Escolástico del Bosque', 'escolástico.del.bosque1@test.com', 'admin', '$2y$10$1mu8v/XGO2CQ.aGKQPTNRupifWaUyRY/HJcP8zk06zahfLZHLuY8C'),
(955, 'Marina Vergassola', 'marina.vergassola152@test.com', 'admin', '$2y$10$MlJ186cNJqEGqlLWtin4weJVc0ykuVSsp35xdkgOxdYaSg9k1cNIG'),
(956, 'Iker Dhu', 'iker.dhu153@test.com', 'invitado', '$2y$10$7LktvpRs7F2cmdyJ1Sv7qe41phWXwJFcI6V7Oj4XGa02FVIvLFVcu'),
(957, 'Yoringel Eire', 'yoringel.eire2@test.com', 'estudiante', '$2y$10$e3JU1uuWIuwxQIPMUx9iAe6gN6jQXELjEfDt3.z8UQGtEZQLqthOW'),
(958, 'Cojoncio Honrado', 'cojoncio.honrado154@test.com', 'admin', '$2y$10$oXl0azfgMcnpONzjwqPB9.Us01iWrdGY9MXX3v0G49r9LIdJbUQxS'),
(959, 'Ben Aritz', 'ben.aritz3@test.com', 'invitado', '$2y$10$z6RiLG6GOiUsiAHg8g3Ocui0chcRkZTQ8IFprp6FIoLBr4PZsanGS'),
(960, 'Pedro Salido', 'pedro.salido155@test.com', 'admin', '$2y$10$EWVrrRe5lk1eZjeHWuCVDuAJpYyI2wXDe38lj5adp.2wY8mC4ppaO'),
(961, 'Froilán Torres', 'froilán.torres4@test.com', 'admin', '$2y$10$aBHkXQRztGJeTsvUGycjEO3gLAkFUHTMFj5lpIfd4ir75U9nPb2ia'),
(962, 'Iker Elba', 'iker.elba156@test.com', 'admin', '$2y$10$I8/PE6cXnut7kVs2LIhiL.yrpQi5u95GwKcnCtNIdIH4eqjOWX/t.'),
(963, 'Jofre Gil', 'jofre.gil5@test.com', 'estudiante', '$2y$10$B1G1vRhmsbV..w83QsLuzu51FFOwOy4nOnGHGE1v1Ggy.vmFF.gzy'),
(964, 'Valentina Cremento', 'valentina.cremento157@test.com', 'invitado', '$2y$10$Ypsun2.jPC5HygqpLcv9Y.vEMFxV6Jq6YBKNq/hbFMM0BVyx/UTm6'),
(965, 'Diego García', 'diego.garcía6@test.com', 'estudiante', '$2y$10$wzT8oT1lhnLbjo4ZoxPbkOKXulqBYL/p/U.KZbDuDCfu3g3MDDdLq'),
(966, 'Leo Botelli', 'leo.botelli158@test.com', 'estudiante', '$2y$10$SMA7WXBfsHBddMx4VyZB0O60R75fbeu4/oHJx6Y7AjSIHk9wAB6z6'),
(967, 'Ricard Calavera', 'ricard.calavera7@test.com', 'estudiante', '$2y$10$8XFanLH/LgUF/2vmAyFWZ.92iBU2Nsks0HntRHJHUiqMdYVUVkGqq'),
(968, 'Yorinda Escolástico', 'yorinda.escolástico159@test.com', 'invitado', '$2y$10$T25kFHks5e22zok5SR7eoOpkpeMKOd6wyq5nUankNRW04s82NEgi.'),
(969, 'Raquel Altagracia', 'raquel.altagracia8@test.com', 'admin', '$2y$10$fQklll0EV1MNJoqAJoJEYet/f3M9VV1bp6P.wyGQiAw0jhD2yjoaa'),
(970, 'Piedrasantas Esario', 'piedrasantas.esario160@test.com', 'estudiante', '$2y$10$50dBD9crTtQj7V3L7X8.SeJvjRf9Xn1c0kcpOTkbLkBBegiioYEVi'),
(971, 'Alyona Pantaleona', 'alyona.pantaleona9@test.com', 'estudiante', '$2y$10$hbft1iqqAYqnUG1eIv.Hke4W8qsN1LrfU8dsqLw3fXQsP4cP0TYRW'),
(972, 'Marina Cipriniano', 'marina.cipriniano161@test.com', 'admin', '$2y$10$qDaCufwkWyn3WavR.bwNZupAt6sHsOMVAVTDMySm/Rw60V12c.qK.'),
(973, 'Pedro Paramí', 'pedro.paramí10@test.com', 'admin', '$2y$10$56G3Bm/zelX37ZWPF8IjGeqJ9QeOYIOYmDbbHw0mrihAtOrWzBTN.'),
(974, 'Abraham Arrimadas', 'abraham.arrimadas162@test.com', 'admin', '$2y$10$ws595C4Hvt0xA9zz6wzr/eXSxWpGgQto5EYKf.18VUPng0JE9ZWcy'),
(975, 'Markel Yoringel', 'markel.yoringel11@test.com', 'admin', '$2y$10$GRXkkhd5VZsj2VfO1bYaFu.V5dIjDDp6QovAdh5dxkDSKBIAE69rC'),
(976, 'Luisa Escolástico', 'luisa.escolástico163@test.com', 'admin', '$2y$10$1pBiddqXhZffMGkBaF1tFuIolfDiIzrJSh4ODR4eM2sJHdgOkIT7y'),
(977, 'Paz Expiración', 'paz.expiración12@test.com', 'admin', '$2y$10$ImxAbGKbzECy7S6jWmhs/.bcdNb3v9L5VdavaMsXRZV1nEmBerDKu'),
(978, 'John Marciana', 'john.marciana164@test.com', 'invitado', '$2y$10$YBJYR0fzfhaoAub5rw0zGePH4e.jxsFnHR2KeLKnbet0M1aqO/6xq'),
(979, 'Felix García', 'felix.garcía13@test.com', 'admin', '$2y$10$y5piS851LUNeuCdh33DBkuLp55b2nG5PWF7LX8iJ16EcJtDubkyUa'),
(980, 'Sandra Elba', 'sandra.elba165@test.com', 'invitado', '$2y$10$EBkRmhYMK9T1zHGjPauA9.c2uywnQtUc.uw5ivhdUMSYCj4KkATqm'),
(981, 'Froilana Fermin', 'froilana.fermin14@test.com', 'admin', '$2y$10$InqrMkrHIuG9VY4Bp28oSOmPtGsG6yuXLUfWNs37EPM3CvsnL3bv.'),
(982, 'Eneko Montada', 'eneko.montada166@test.com', 'admin', '$2y$10$bWu.Lf6MZMyudp8wvAmAQ.Rn7i8ab9QlN9ddC/4u5Xz83vHv0aUS2'),
(983, 'Rosa Yorinda', 'rosa.yorinda15@test.com', 'invitado', '$2y$10$hXvgP6mJaORA5qAHLiR3zeErNDpxUO2AjZSeA8ggcsf6yuzgkFfva'),
(984, 'Marcos Gordo', 'marcos.gordo167@test.com', 'admin', '$2y$10$YNSKpaMLnVnqRSL81FgtbObhZq7DtKh5A/r9CwrJc34iZU4zEM/YK'),
(985, 'Armando Gordo', 'armando.gordo16@test.com', 'estudiante', '$2y$10$x4Sw74mhcAXondS2.V64Puf76sytNeb4.F0.bRU5jypzARMr9af2.'),
(986, 'Miles de Barriga', 'miles.de.barriga168@test.com', 'estudiante', '$2y$10$Tz9XQ266ecQvYCYWLpWng.YO5kcZzF.2SOLhnWxvyG6iyyh8W/sW6'),
(987, 'Argi Gumersindo', 'argi.gumersindo17@test.com', 'invitado', '$2y$10$4Hx8rVDEE6s0.DJJIUbnE.E968sOb6Jt0nYfCpVMMdTce.0.OebuS'),
(988, 'Froilana Segura', 'froilana.segura169@test.com', 'estudiante', '$2y$10$3gz5mVkFsWJJYyeLuCBlTOfT7dIXC/k3zq5e1.FGUihWTRURqaD9O'),
(989, 'Bojan García', 'bojan.garcía18@test.com', 'estudiante', '$2y$10$z1A/yLyvfSZSKy6DfClPMuwSTWVFTmslYJeju6whBCV5f/PGoy0Qe'),
(990, 'Markel Mento', 'markel.mento170@test.com', 'invitado', '$2y$10$aYENuBAD57egF8o8AYqKwuOxTFfC4LwMBv9RfkpoZ.cZXlpZ3YWlW'),
(991, 'Abraham Perroverde', 'abraham.perroverde19@test.com', 'invitado', '$2y$10$kt.4plVkUAnFHoTMhkVek.VU/tPHZ.uVdOr4mqAzxAdfLNgwXnBci'),
(992, 'Jezabella Díaz', 'jezabella.díaz171@test.com', 'admin', '$2y$10$GweVNuQzDOhSR8JJhCX0TewZquxsZX4eWrtuvPc/LmayTuucbiTU.'),
(993, 'Jezabella Arnulfo', 'jezabella.arnulfo20@test.com', 'estudiante', '$2y$10$2xHVTC5if/prQ97c5Xxi5Oz2l1IxNeh5orG1Fs8GnnexBHH80cNr2'),
(994, 'Oier Cortada', 'oier.cortada172@test.com', 'admin', '$2y$10$xP8FnVAfyPz9hjmCHQDGf.9Ypy/JbinM48jGds6zZ9iGMeQ0WRKSW'),
(995, 'Ana Gol', 'ana.gol21@test.com', 'admin', '$2y$10$Yp4JgvEu1OR/jlVo6WijTOfY38vt2jNUSAQVDrTAeGKcNEXEyOwci'),
(996, 'Drac Miles', 'drac.miles173@test.com', 'admin', '$2y$10$s0wY5wWKwbSSnRxd0GY5XOeaOE2w0aFqJc1yZRKEWR.Xao9KYJQbO'),
(997, 'Nacho Martínez', 'nacho.martínez22@test.com', 'invitado', '$2y$10$V.XSNxyG6VyX9h0NE.942eEFWFHdTUcbMYndGzSkONL/xwwRuQrRu'),
(998, 'Peter Gandula', 'peter.gandula174@test.com', 'invitado', '$2y$10$EV3gj8doInnw/qG1dtrgle3YOK8cllrzt/HPlyIL6zV9EpXMTemSq'),
(999, 'Dolores Honesto', 'dolores.honesto23@test.com', 'estudiante', '$2y$10$Y.qfVrqOPoElZ0r.TrJlWuZ0fJLp8hPe1jv9EmIW6dExqpBnRUini'),
(1000, 'Milos Mingo', 'milos.mingo175@test.com', 'admin', '$2y$10$s6nuWdVOyLna2AOdo2XD3ud5TqF9DFkPUbRip3E5WAhqQV0ekQm0q'),
(1001, 'Patxi Elsa', 'patxi.elsa24@test.com', 'invitado', '$2y$10$brbY0hDbZ0t6mTSoh2WJJuC8evRWGGrFaoqQST8pCClfqukkJ5flO'),
(1002, 'Penitencia de Barriga', 'penitencia.de.barriga176@test.com', 'invitado', '$2y$10$81PMjW2bKWC6AxKDJhx6Y.EfYih7GvrwW2EAffwSl5AqW2U9HrW7S'),
(1003, 'Milos Arrimadas', 'milos.arrimadas25@test.com', 'admin', '$2y$10$h66.g/YGRblCxYTOYF6uQeo8Tzo1Pi44SpLE6Nqj9AVfKMQJdefLa'),
(1004, 'Elm de la Repolla', 'elm.de.la.repolla177@test.com', 'invitado', '$2y$10$qPQr6tQtC6DYNenp1XjCkO0paMIxgsLV8Ilk3xnZZz05U5En7dEJ.'),
(1005, 'Burgundófora Cojoncio', 'burgundófora.cojoncio26@test.com', 'estudiante', '$2y$10$JRzqzocogQW4teiegaOaHeva2pW4vpcI8oXgIGPPrVvx0W8Fv6mqu'),
(1006, 'Alejandro Cipriniano', 'alejandro.cipriniano178@test.com', 'invitado', '$2y$10$B0P0eipJNqJVm4PRODthi.Td/wKP/cs/wmyKYqApDDwI.UPUyq2x2'),
(1007, 'Arsenio Gordo', 'arsenio.gordo27@test.com', 'admin', '$2y$10$fr80TKO8JUY8CNq7LR7LluDr/26mjL919/1anEXxlNW0j9H/Y2.9e'),
(1008, 'Alexandra Marcial', 'alexandra.marcial179@test.com', 'estudiante', '$2y$10$kj7Qbnnf9d1LGzvzzS6pDOPPSf73PJwkEf9PBqa6EkORjXFrHeYvO'),
(1009, 'Sergio Protasio', 'sergio.protasio28@test.com', 'estudiante', '$2y$10$4yTMvJR9EH9GdZfK0yvBLuAtkfz0SpCN/IeyFwNr3/thCsLq3XjY.'),
(1010, 'Eilán del Bosque', 'eilán.del.bosque180@test.com', 'admin', '$2y$10$PoHETdNrCMHvQQ84Yg255OlJYTyyZammeE06PeTbbOWJdmKU6d9Be'),
(1011, 'Sonia Seisdedos', 'sonia.seisdedos29@test.com', 'invitado', '$2y$10$OsZAfbD3rDO5KZwzZlmtBunfcgvqkXgQTPH924IN3../rBFxotJ4K'),
(1012, 'Ana Busado', 'ana.busado181@test.com', 'invitado', '$2y$10$NI0CbLeUMbxp9WMBu4aFrOvcJIU67eO6C8jkbdxlBwSy2MI3GkHFa'),
(1013, 'Amadora Segura', 'amadora.segura30@test.com', 'invitado', '$2y$10$paEzCL.GNTQ/l.clFWq8oOPuaSmUxInrJ.87KK82iaIXITU38/4Wq'),
(1014, 'Pantaleón Gol', 'pantaleón.gol182@test.com', 'admin', '$2y$10$eyzajqPOU0ZdLGU9xZd1gukK14XNtB.eviFb6OdRAp.B2BUh7qPw2'),
(1015, 'Thais Paramí', 'thais.paramí31@test.com', 'invitado', '$2y$10$t.znndcg003wCeuebw0zaOzkOC1gP8Rhv2VYhWiCub4fUkG4fKCqu'),
(1016, 'Carlos Flores', 'carlos.flores183@test.com', 'invitado', '$2y$10$fJ6h2nybpTGW7VoI97niuezEy3TL6oOh0rRtztSp4DhIkR3JfY/NS'),
(1017, 'Elena Torres', 'elena.torres32@test.com', 'invitado', '$2y$10$2sliwHG.2lv9K92XwIQAsuDBxB0onF8ad9dbkE0b7BsrTqTT44UUa'),
(1018, 'Aitor Gol', 'aitor.gol184@test.com', 'invitado', '$2y$10$GMb8a7zmOh0KNN6iL6MzjOP9SpjIAhB3vgaSBSC7pkvPUkgVTtZk.'),
(1019, 'Marina Piedrasantas', 'marina.piedrasantas33@test.com', 'estudiante', '$2y$10$P/VMc/na3o4okytJPwu1GuSTBpUfi2cSiezbeDc2egZ67sRIcllQ.'),
(1020, 'Carlos Pieldelobo', 'carlos.pieldelobo185@test.com', 'estudiante', '$2y$10$42F.l0fN./RGy9QyW3LHKOa7QYQtufnhp5P7SwyIbS.gD4hDW2oCS'),
(1021, 'Abba Leona', 'abba.leona34@test.com', 'estudiante', '$2y$10$e2Yf5gzrKYZa9.4L68JwuegJnyhCvzERKmlLpvTHpprMfbMbPG1c6'),
(1022, 'Milos Gumersindo', 'milos.gumersindo186@test.com', 'invitado', '$2y$10$Wfm69sgXbiO/aKWQ0Pxk8eAtktQ7YHvPGUMHxcudlO9ZAC0W7F6T.'),
(1023, 'Pantaleón Flores', 'pantaleón.flores35@test.com', 'admin', '$2y$10$xK6thzQa1XdpF8zhyoLWrO5lCIHCgpCXPKns1oLCxhdayLUqzaw8m'),
(1024, 'Pantaleona Aritz', 'pantaleona.aritz187@test.com', 'admin', '$2y$10$KwcSCcnw0aHqQ5W1PtsvwuzmKxxFwtc/7OhDVC5kymczrEZYJRYqi'),
(1025, 'Diogenes Luzdivino', 'diogenes.luzdivino36@test.com', 'invitado', '$2y$10$cYCMPk2L98AVs0Oc5JbE7ug9WUgkDlAbyB0H5.Wd3RxT8QpSHH3y6'),
(1026, 'Paula Tresado', 'paula.tresado188@test.com', 'admin', '$2y$10$Wclk3h85sxl0z/az0x4iaeNTBxvNl.PKhTb4VLJQnydWemK4.Twye'),
(1027, 'Covadonga de Cabeza', 'covadonga.de.cabeza37@test.com', 'admin', '$2y$10$1.R9xy31yOlyNixWTvar/uQ.4AUh.orqwgcw9g3CxcA4XavoeIAiS'),
(1028, 'Tesifonte Gil', 'tesifonte.gil189@test.com', 'admin', '$2y$10$vl0itLrKmKJJm/8UlREga.FcE0iWox6zl4Fgyso0hR5ixeYilennC'),
(1029, 'Elvira Marcial', 'elvira.marcial38@test.com', 'admin', '$2y$10$S/lao1VWDJ5PrpOVava8iexxT1VX0cs2IAe0cVvawmO0vpkdUFY7m'),
(1030, 'Rosa Segura', 'rosa.segura190@test.com', 'admin', '$2y$10$OzQMGu9VzdPl3j2vhX0aWu5BEXiU20LL.FcfSMk8a0CfvApqDDQ3C'),
(1031, 'Jofre del Rosal', 'jofre.del.rosal39@test.com', 'estudiante', '$2y$10$jCOePvNy62/AzF4WGNIQd.EgQ9kMsmo9SSg.ML97AaSkHX7p/FWGu'),
(1032, 'Montse Díaz', 'montse.díaz191@test.com', 'invitado', '$2y$10$27TwagpSzL3Xkcc59MAaKeNW0pMHBUUaIJ6erVmdLbg7gRpQgqWPe'),
(1033, 'Penitencia Silvo', 'penitencia.silvo40@test.com', 'estudiante', '$2y$10$UcvcHDfgl8rmSiI4giViIODv5E7jfLseY8BiQlfdbqMo0v.r2Xqq.'),
(1034, 'Alexandra Salido', 'alexandra.salido192@test.com', 'admin', '$2y$10$8rG8qSwf4im0CV2jE2AGgenbWNub4OAvaUPhzjlRNrJa8J.5EABPK'),
(1035, 'Laia García', 'laia.garcía41@test.com', 'estudiante', '$2y$10$PL0AXcJClqKG4fV4zzv0EuY8QpcJ664pgjzkbW3cK22Yl6Z9sOLzO'),
(1036, 'Montse de la Repolla', 'montse.de.la.repolla193@test.com', 'estudiante', '$2y$10$zR2HmYNQIt2c01b.h4y7keUplG7xXL.jv8JL0hNcNXEzKCGgmWgT6'),
(1037, 'Abba Alcoholado', 'abba.alcoholado42@test.com', 'estudiante', '$2y$10$zq0bI7IjET7PfqrGoPynLuOLQfsbCmTFNsH1ehtSZaeqIyM/pV3y.'),
(1038, 'Aaron Apolinario', 'aaron.apolinario194@test.com', 'invitado', '$2y$10$ROm3svd9fGm7uEcH1XjP0..ze/mQR/vxvvEH0JUUIhXY9PurGkufy'),
(1039, 'Louis Trozado', 'louis.trozado43@test.com', 'estudiante', '$2y$10$64zKKkgLfuXtngxDAT4.u.9ycp6aep1h0enI.6a1Idr2EgiD5m/i.'),
(1040, 'Elba Apolinario', 'elba.apolinario195@test.com', 'estudiante', '$2y$10$z0Cc//FtezBzLilYceAGEO3sAMmqpbe5p6WFhlw.OXdAGmEkbe.fu'),
(1041, 'Iria Yorinda', 'iria.yorinda44@test.com', 'estudiante', '$2y$10$/ajjXsoQiQAbCcLiHonDNORahhTNhEwXO00/erE9BApthC3zFomgi'),
(1042, 'Marcos Moto', 'marcos.moto196@test.com', 'admin', '$2y$10$Y.53thNkmqpRIqdCTPU5MeU2nyRSi02GdBPkgSu7gbuEcpb6Qc1Om'),
(1043, 'Duncan Leona', 'duncan.leona45@test.com', 'invitado', '$2y$10$ZPngVx43bgnJMluj2jg7OOfeauF6lOo8AZ15g7EDjCeW8JP4WFsCe'),
(1044, 'Jerson Cuesta', 'jerson.cuesta197@test.com', 'admin', '$2y$10$MLNF3KouutkCpge4XwvJZOANFmwgHFjFxkrKnznYCAEIp2SYL.AYG'),
(1045, 'Abril Digna', 'abril.digna46@test.com', 'invitado', '$2y$10$YeAY2WSDq1n9T2z/E2tUNeJeGV93tltuxYsMVdXrEJjO6lTgL0K76'),
(1046, 'Jorge Fermin', 'jorge.fermin198@test.com', 'estudiante', '$2y$10$XSWbkbuSn9Qy6ITEC5SK3eHHA3Q9QUslUXkW5cNJOJqB6uM0f5.W.'),
(1047, 'Isaac Marcial', 'isaac.marcial47@test.com', 'admin', '$2y$10$tdgXIMsnQzlMR70Z90doW.AmaqfMVZSFFaUpKBi1UC/j.1fzoPFwO'),
(1048, 'Dolores Lioncourt', 'dolores.lioncourt199@test.com', 'estudiante', '$2y$10$btQGo2sVTqB93Jp61EoRPuNe7XjYDhRoO2HjBEMCi/6lHAbbq6Cja'),
(1049, 'Yorinda Kermit', 'yorinda.kermit48@test.com', 'invitado', '$2y$10$u3T/FKKPMEWzC2dxM7pG/utxbNvTQghDI79fuvWOPM8b4.rj0Vnzq'),
(1050, 'Jorge Arrimadas', 'jorge.arrimadas200@test.com', 'estudiante', '$2y$10$ef.qWQggPxFzQVV7MHucRe6Rwhw.BYnVZUkdCDqvW2oFHPDDQrQWa'),
(1051, 'Pedro Iluminado', 'pedro.iluminado49@test.com', 'estudiante', '$2y$10$H5Mo2zR1SR.yg2jXAioPIed9x1XLOGuiaIop3jSWN8T5B4CCKWulm'),
(1052, 'Rúben Dhu', 'rúben.dhu201@test.com', 'invitado', '$2y$10$5dTUSDmKLggG6wupxx0TbOrdrFVC1WvzLO5lC7MV3psPL4vvr6tQO'),
(1053, 'Ana Jetson', 'ana.jetson50@test.com', 'estudiante', '$2y$10$5fMSzNgKacHYL.bnH8hDjuzSJ1vShTU1AR8WfW7kgr7q4WqpPpITO'),
(1054, 'Pantaleón del Carmen', 'pantaleón.del.carmen202@test.com', 'invitado', '$2y$10$vc3LM0bNi.ZWUm1qh/QMvu3kLt/xAyvLxiyCnimQ084b/uMFNU9Vq'),
(1055, 'Iker Alcoholado', 'iker.alcoholado51@test.com', 'invitado', '$2y$10$U2kFWrecOrC411.KPsgX5u1FHLjKfYab8sYPcQJ9UzWqs1PO1ZwFa'),
(1056, 'Diosnelio Piedrasantas', 'diosnelio.piedrasantas203@test.com', 'invitado', '$2y$10$1saSTrXXaA4JihC7ABdoK.6H1iFxTy0ay4VsHux1TezAteNTEcX.K'),
(1057, 'Eros Alcoholado', 'eros.alcoholado52@test.com', 'admin', '$2y$10$x6HZUQksuHbr/BrjQVthtewos4ioiP4DbOSWex/MbBth4b9iJb/yK'),
(1058, 'Kristin Martínez', 'kristin.martínez204@test.com', 'admin', '$2y$10$Ll4iGM/W6xKaychxQV2kr.2QFp4LV8tGaodLKExYfPjdLv.ke9L9G'),
(1059, 'Rúben Surero', 'rúben.surero53@test.com', 'admin', '$2y$10$IDfgeSZmyrZL9lFNH5Q0cesEiTL8WcHBW5uWXYht67PmN./49DIYy'),
(1060, 'Iria Elso', 'iria.elso205@test.com', 'estudiante', '$2y$10$lskTFliUJ/zYa8YXngfIyu.AUSeE1yFIcVvilk6E4CH2fvKd4EL2W'),
(1061, 'Markel Pieplano', 'markel.pieplano54@test.com', 'invitado', '$2y$10$85FLeVg.WwvhN0FlCh6OD.YKyjbuAk4gy2LN1IcOXUNuESrqGikEO'),
(1062, 'Ezequiel Alegre', 'ezequiel.alegre206@test.com', 'admin', '$2y$10$LRGyIz/AFGQR/AxGf6UmruVTL3dPd7ebQrrnHFSjj9IByjKDtSWYW'),
(1063, 'Paula Ruiz', 'paula.ruiz55@test.com', 'invitado', '$2y$10$GNBgGYcw2Ph5xe16Ph2HdeliUXAysRotrqoq7nTEnGs9WaBk/kUR.'),
(1064, 'Fulgencia Honrado', 'fulgencia.honrado207@test.com', 'invitado', '$2y$10$oMXn6Lk1dHuzYyI4sWs3OeKCM3s/nhFCLsSMcnkOyrmsJpELulawe'),
(1065, 'Valentina Cremento', 'valentina.cremento56@test.com', 'admin', '$2y$10$gn509kzuzrvcYn1XD5D1E.S8KrFR82gvCre0J/cWeRLsFXKs.JCnq'),
(1066, 'Arsenio Armandez', 'arsenio.armandez208@test.com', 'estudiante', '$2y$10$BhgA5ZcH3KOP9GTDvFvBLeK98fxOPZAKED7KK0jnYNPT6CQDdgO0i'),
(1067, 'Kristin Fina', 'kristin.fina57@test.com', 'estudiante', '$2y$10$GKOIW8.RELiYMjOwMJ8Hl.PxvoGT9KjhTkE9JYGSBU4u6LcBD9fX.'),
(1068, 'Brais Yorinda', 'brais.yorinda209@test.com', 'admin', '$2y$10$IsLghBs8HSxr2h7VlwtOkuns0JFybiH4P55.JMxetv7fNwUhXDN.G'),
(1069, 'Aritz del Carmen', 'aritz.del.carmen58@test.com', 'admin', '$2y$10$A0ciHIIKvAj18EalpABOk.iQdnR8p4SJVUph3KQX6tPaqAiQoCTZi'),
(1070, 'Segismundo Pérez', 'segismundo.pérez210@test.com', 'estudiante', '$2y$10$.9ZO.9dayibqjH7Pn.CoXuilt9Fw0d.q2zE.3bkqkqlFAi8xifRlG'),
(1071, 'Pantaleón Segura', 'pantaleón.segura59@test.com', 'invitado', '$2y$10$56/.P2WL0x0lDmg19UoVJ.ej09wMsNnfYjJvrc03hJYfpMzv8Jxh2'),
(1072, 'Lucía Elba', 'lucía.elba211@test.com', 'estudiante', '$2y$10$DuYIYz7dJlKEd.79Bqi2W.pt/iUUk/t39YnxOKaRN7U58iYyvUs9O'),
(1073, 'Fulgencio Gol', 'fulgencio.gol60@test.com', 'invitado', '$2y$10$PLyLvjvIY3fMQiD6C52Wtu4PmxJsnaof49I2DEjlOtgHuT.Refi4m'),
(1074, 'Andrea Ladislao', 'andrea.ladislao212@test.com', 'invitado', '$2y$10$wG4r1TWvaoH.bh7qKTB5gu6LKEkLKG6ahLvpDNpTuCWlf/faofaSe'),
(1075, 'Aitor Ladislao', 'aitor.ladislao61@test.com', 'admin', '$2y$10$N3UnpJBR8VibiOfdyrfW7OgKcEi7FZYN5YBGSSTtsbUnuG/shh9JC'),
(1076, 'Marc Oristila', 'marc.oristila213@test.com', 'invitado', '$2y$10$Wl1y4tAXgso8/XJhEmV4eeuigo0YHeK6A6n37UB5nBqEe/Zp5BSba'),
(1077, 'Elena Zas', 'elena.zas62@test.com', 'admin', '$2y$10$S5ZPp0qENw6nVbO.wZTktOh6iF59LK8yc8CtzkO4.YR5DcqAIcuB2'),
(1078, 'Markel Cojoncio', 'markel.cojoncio214@test.com', 'invitado', '$2y$10$40.ilaaoJjxCtgLchA3f..4ab.RgBfBhkcfIDK8UP1TD7H3vfT7X.'),
(1079, 'Elm Masdeu', 'elm.masdeu63@test.com', 'estudiante', '$2y$10$BIzfxhdPBXIK/NbX78uLDOxD.VOeZb9PKHOWXcPn4m28dZH/Cf4O6'),
(1080, 'Alyona Segura', 'alyona.segura215@test.com', 'admin', '$2y$10$PMIWWwDs/dxbiMrBs1nFeOE1N/f864YD.V42gTZcfXmpm/3Wkp2Da'),
(1081, 'Jerson Sánchez', 'jerson.sánchez64@test.com', 'admin', '$2y$10$pUZ8X8LJnzFjZ1lTJhW0i.FVXaQzu.dV0cx/Az9O3GMY9oTFRaMaS'),
(1082, 'Renata Mento', 'renata.mento216@test.com', 'estudiante', '$2y$10$eqrFgz5D/zpJT6IIc59VQuFJl1M/m4J6JnoWXIlCgryt6JWiYkCTC'),
(1083, 'Anne Gómez', 'anne.gómez65@test.com', 'admin', '$2y$10$RVhF3pz6XSTrW4fr8b7KsOs5HdXAp1WX42CZYaWB04zpkhjTtHtzS'),
(1084, 'Segismundo Artemisa', 'segismundo.artemisa217@test.com', 'admin', '$2y$10$4JlMU31w8JvvxdUM4G9J5ebtjNCZ6oLD97rlYY767s.ezvI61kj2S'),
(1085, 'Hercules Arsenio', 'hercules.arsenio66@test.com', 'invitado', '$2y$10$aD.ggZhXUlr7BSd2v9jGxebynK0lLr6XLub.VLLXaT4hj96oLSce2'),
(1086, 'Lucía Alyona', 'lucía.alyona218@test.com', 'invitado', '$2y$10$LknE9NIF83yutm90Yljhku8bPIAk2kDR06JuWZMLqGhM2w6zgVax.'),
(1087, 'Silvia Elsa', 'silvia.elsa67@test.com', 'invitado', '$2y$10$k8oqhFG/eY85NU1a3PCfP.XBDIRd3igmre5Uj7SFP4E6J.owsip4C'),
(1088, 'Expiración Gol', 'expiración.gol219@test.com', 'estudiante', '$2y$10$0TE82NqZeI232QxAtVRso.bWvmBF.2EQWCAwY5M4ZbOcuuv4C8kU2'),
(1089, 'Sandra Arsenio', 'sandra.arsenio68@test.com', 'invitado', '$2y$10$8LO19CUCSbsqaoA2znvNqegNZeyBw.uxkLAK5A2GV6FBC3ViIkSpy'),
(1090, 'Marciana Zas', 'marciana.zas220@test.com', 'invitado', '$2y$10$m2rfs/TzgFmIGTR5QNuAzO11rBQw45FsLXLCKBxMw2PpPm1CqBFhq');
INSERT INTO `usuarios` (`usuario_id`, `nombre`, `email`, `rol`, `contraseña`) VALUES
(1091, 'Escolástico Japón', 'escolástico.japón69@test.com', 'invitado', '$2y$10$3BUpc6MzTE7tJlUGpe1.hOuualedJfT5Kox34eTiBfQHrGYgp5JCm'),
(1092, 'Elm Montada', 'elm.montada221@test.com', 'invitado', '$2y$10$Q1F3Avu0dzV.CQrHZK8gX.xi3Aaxb3Y3UyQP3ZmLsgU.M1TKWcvxG'),
(1093, 'Digna Patel', 'digna.patel70@test.com', 'admin', '$2y$10$ezIa3cVAEpBTpAA8HKCuT.UVypB8Usou9rS7/wWQh0bU2DzCEFBWW'),
(1094, 'Elba Sandro', 'elba.sandro222@test.com', 'estudiante', '$2y$10$I05JSh6KCseMJ.UmPluhWulqhjcvrqt5r8HDOhai7/fCpr6UxZ6Rq'),
(1095, 'Drac Hercules', 'drac.hercules71@test.com', 'admin', '$2y$10$zmruXYa7RWlO9ChX530kMOygKPsUZWCUKsEV7aFDbXcnLzKfKPGL6'),
(1096, 'Gumersindo Gómez', 'gumersindo.gómez223@test.com', 'admin', '$2y$10$j59.R9jG7lHUizmPb7UnReFEjAsd.hWBuu.mUdTXFrzMXfX4vb4rq'),
(1097, 'Anne Altagracia', 'anne.altagracia72@test.com', 'invitado', '$2y$10$Z/XCxenh60j1z0vlttnMk.pX16rtCKUCvWBgPTzGkcHO5GvNspYWu'),
(1098, 'Rúben Artemisa', 'rúben.artemisa224@test.com', 'invitado', '$2y$10$h47vMR.tNisRgA7ZtnJYA.8oZoemkCiLOkKNHAywML8c9aWz2TqhK'),
(1099, 'Salomón Gandula', 'salomón.gandula73@test.com', 'estudiante', '$2y$10$VqaPksq5Ko63FjVrcWds/ORlyUt7iHDW0Dp9A1Z/MPTz43Bli3EfO'),
(1100, 'Paz del Carmen', 'paz.del.carmen225@test.com', 'admin', '$2y$10$RhOzw/.cIKRHwFHOI4ePbun/e3i5ZlUM7hF6xAveG8cIcDGR5qgVG'),
(1101, 'Eire Jurado', 'eire.jurado74@test.com', 'invitado', '$2y$10$tM4U6cGo4movkm0bWNz1IO07iCDchp6StiT05/gCnlW/oYdDTMV0m'),
(1102, 'Lucía Bronca', 'lucía.bronca226@test.com', 'admin', '$2y$10$XGZF4Z9BNIwc4SdfuG1nDu06O0N1/ZphoH9jaMrWCIMnYYBQhYxAi'),
(1103, 'Blanca Montada', 'blanca.montada75@test.com', 'invitado', '$2y$10$UCNMnosX2fZyJd5KZEmJmuRwVWky.4CB5MgmmQxFls3VMSzVtHJyu'),
(1104, 'Marcos Pantaleón', 'marcos.pantaleón227@test.com', 'estudiante', '$2y$10$tusu8EsGEIjUw92a9ZkqK.HApN1BygdCwuRO8GpTFjHczEj6kuiO6'),
(1105, 'Diosnelio Burgundófora', 'diosnelio.burgundófora76@test.com', 'invitado', '$2y$10$AiSZhtRkoV7iC9i2yBcTPuBGdbdnnapJPqCgCl790WSJgWmDUTP52'),
(1106, 'Kristin de la Paz', 'kristin.de.la.paz228@test.com', 'estudiante', '$2y$10$QsbOc8TbGL8VLmccO7W4Y.t4gryCTm6ixjWcj4IjJXjelzKTFACcy'),
(1107, 'Anne Eire', 'anne.eire77@test.com', 'admin', '$2y$10$9yUOTKs/jBfrIPTim06yuuCskO.K1SMTNS/b4YZT6PcbZETFvbQ8m'),
(1108, 'Thais Patel', 'thais.patel229@test.com', 'admin', '$2y$10$Zji1glX9N6NJgSncMUuVEuSY6kO4I6Ahtk4ClOIa1Xaf8As9d7NfS'),
(1109, 'Kristin Moto', 'kristin.moto78@test.com', 'estudiante', '$2y$10$UedZJBe0T6tPsVR.rlnC6u2gLX/zy8LbnE1WAKHy4MsvPdTf7liFm'),
(1110, 'Elm Nieve', 'elm.nieve230@test.com', 'estudiante', '$2y$10$eGydtjdOFzniAkado96dxu4f/aZH9/j6f7oO0UD2GUOx87kbY0W6C'),
(1111, 'Bojan Kermit', 'bojan.kermit79@test.com', 'invitado', '$2y$10$nLf8gBavzqyCJ5TCB5Hp0.Jve4lgOErMDygP7UEseKwpwlITKjMRy'),
(1112, 'Paula Gumersindo', 'paula.gumersindo231@test.com', 'estudiante', '$2y$10$DVCPrIDEAgyIlyOMcr5MlepG7j5989BqKPE5UDCRWy84NuZufJhOC'),
(1113, 'Alexandra Zas', 'alexandra.zas80@test.com', 'estudiante', '$2y$10$Dhm1DU2In7O8qeUh/rFq6.eR7sR1lboIVY55NXyA3NZydk1M6db7i'),
(1114, 'Penitencia Piedrasantas', 'penitencia.piedrasantas232@test.com', 'estudiante', '$2y$10$.GfFhOGhQc9xrPIHBE92OuhEzdnOH5PIciumgb54FUn/QdF.1n87q'),
(1115, 'Paula Alyona', 'paula.alyona81@test.com', 'admin', '$2y$10$Yfc/IZHd.DWVICs2jyWSm.bQh9OTbRzfD/zJXT7XGAoCvkSY.xGQi'),
(1116, 'Arsenio Yorinda', 'arsenio.yorinda233@test.com', 'admin', '$2y$10$QFNN.TD6kS1seCar09jeXOnMmXBQcfnM/.wbjtn8.7HOgOEs5lFqi'),
(1117, 'Sergio Trozado', 'sergio.trozado82@test.com', 'invitado', '$2y$10$T3gYtkvyUueV6bRdCDTsAOd1uCHiWPqskPE0TnYbdonZ4khvny7EC'),
(1118, 'Pantaleón Díaz', 'pantaleón.díaz234@test.com', 'admin', '$2y$10$ANdd5K3kDCxFdVtu.Ou3CeuHxNuPV1wUg66SOwehd10/qoF2fRq.G'),
(1119, 'Enzo Gol', 'enzo.gol83@test.com', 'invitado', '$2y$10$5a/D93Tpw6NgqnGGNInHge4B4j.Yk/j9XtZE4FusGklpoM/3zuIp6'),
(1120, 'Mikel Alyona', 'mikel.alyona235@test.com', 'estudiante', '$2y$10$b0UMBIBOwWAZAuqAmqj/2.4vOU0WqEpOyjeeayr3Xokz7xkTiOHoS'),
(1121, 'Markel Bonachera', 'markel.bonachera84@test.com', 'estudiante', '$2y$10$8DtgIRunPnpKKkXMqJhfquFNaWn.bbLENtfV1fzUYxpdhtuCL6xAa'),
(1122, 'Drac Delano', 'drac.delano236@test.com', 'invitado', '$2y$10$uMP8MZOtA5KR2nbMLwcZNex.j2eNmcE7y9pBAjJWtQhn.K.fbIjt2'),
(1123, 'David Vergassola', 'david.vergassola85@test.com', 'estudiante', '$2y$10$gCiWWKNoIpAZJuCWoegAN.xjqPu46FA8865GvVS3b60s8uvvs30Ou'),
(1124, 'Raúl Valentino', 'raúl.valentino237@test.com', 'invitado', '$2y$10$8.s7xjUMEuwoIa78xih3MOY0OEvbasL9zMj4i/czWNFpzp3496WK2'),
(1125, 'Milos Sandro', 'milos.sandro86@test.com', 'invitado', '$2y$10$oZE4K1D0MdAgIvrH3OIh9OJoc0tDe/nQ1WRdGT8/4Z..qHKNaBGEu'),
(1126, 'Thais Gómez', 'thais.gómez238@test.com', 'invitado', '$2y$10$CjUxgMowvTHvawz5f7Mw7O9hGWMsJ9RsjGFX1wfA4s23W4ayUq4om'),
(1127, 'Aitor Jurado', 'aitor.jurado87@test.com', 'invitado', '$2y$10$isVc301GA9qbOVoS9aEkuOo7aVCyfdM.IthF1qaIhy.8u.gapLNT.'),
(1128, 'Leiona de Barriga', 'leiona.de.barriga239@test.com', 'admin', '$2y$10$LFmFAAGN13LxkdeUjJeTeuSjtPpzH6wEcavNi88MbkpRVreZYXRFu'),
(1129, 'Zigor Gordo', 'zigor.gordo88@test.com', 'estudiante', '$2y$10$WKXAA3M4elyCGXLccQ9/F.06iajzyNgEEBgYeW6xE/RFw9Zdtj4mC'),
(1130, 'Irantzu Mogollón', 'irantzu.mogollón240@test.com', 'invitado', '$2y$10$ZHGOK7SMYMfvbSlxFGtQo.jexmuTk1Y.p0SqfK2ZJn10qEB40cay6'),
(1131, 'Zigor Cipriniano', 'zigor.cipriniano89@test.com', 'admin', '$2y$10$qoShj4tPKGE8ZwyOAb3BKuNlZuwTXvzonYqcBRvfjMznIQDINjaVK'),
(1132, 'Ezequiel Diogenes', 'ezequiel.diogenes241@test.com', 'admin', '$2y$10$JEwaMVX8ZQoucnvJGRDgdeM0liwkTg85oPmWTOm8yh52r3pQ6vtdq'),
(1133, 'Pascu Lioncourt', 'pascu.lioncourt90@test.com', 'invitado', '$2y$10$8UIOre4gj0MjPx09pj4CWe1C0w82sIEyvUTbSyZAHuPdmvzxKQO26'),
(1134, 'Silvia Kermit', 'silvia.kermit242@test.com', 'admin', '$2y$10$G2RJT1VGL7/X77lkmmucr.NnecpxQP7dROJeWkA/GfD7PkRKiS2Da'),
(1135, 'Hermógenes Gordo', 'hermógenes.gordo91@test.com', 'admin', '$2y$10$/QPMctCi2y9DNeOhb93E/.sO5jjnqoClqppJmRItQzjvChm1zMC6a'),
(1136, 'Eire Hercules', 'eire.hercules243@test.com', 'invitado', '$2y$10$fGu9mqEt1Gn2riAhLi6BIuFmrv/IYY80MkX447cpW.wClPCkskEri'),
(1137, 'Marivega Cortada', 'marivega.cortada92@test.com', 'invitado', '$2y$10$JDEX3g/vdkwR7mIvratZ1eTSOLHq.M64oKbR6uNXnPneB789UNaKO'),
(1138, 'Sonia Bonachera', 'sonia.bonachera244@test.com', 'invitado', '$2y$10$2wB06NDVebYqR2pXOSyYPeCiI6GliqVYJv4wQH2q.Onq2V1ngPXDa'),
(1139, 'Jerson Gumersindo', 'jerson.gumersindo93@test.com', 'invitado', '$2y$10$9XJ/AbbIjuOQbYNEkjLJqepuT9EqrmZaKAO8fY3TZ9hLSUC.8r/qe'),
(1140, 'Jerson Nito', 'jerson.nito245@test.com', 'invitado', '$2y$10$kqka8mF8JwtdtuPGXpJRxu0ujB85NJPBl7vV4BCg6L.akb8pJduEO'),
(1141, 'Raquel López', 'raquel.lópez94@test.com', 'admin', '$2y$10$4u.6d/SvneijJ4oopNH0le6K/zDW2qe.hfs0DRrZZdvMJMWT7sgp6'),
(1142, 'Ladislao del Rosal', 'ladislao.del.rosal246@test.com', 'estudiante', '$2y$10$0SFjR4BWPn3eVCYdzWCKv.JIFu/0N8SBSBrLTKtFfDYq/wbFS6UJO'),
(1143, 'Obdulia Kermit', 'obdulia.kermit95@test.com', 'estudiante', '$2y$10$bTsxwzLObImuNvZWXHwGt.ktWztWMu3cp86AaabHI0pyVLODO2uEe'),
(1144, 'Argi del Pozo', 'argi.del.pozo247@test.com', 'invitado', '$2y$10$AilYS.4jBgbEv9MOxEE.V.vclqZxp5qLJyKKAscPa8h5Lksv1zLP2'),
(1145, 'Silvia Diogenes', 'silvia.diogenes96@test.com', 'estudiante', '$2y$10$q1411gQ6NQfMRSL4KmR3fO/J0Hmjb6vwqgbUe57hzSvghHZGRTV7m'),
(1146, 'Markel Torres', 'markel.torres248@test.com', 'estudiante', '$2y$10$rYUrWIlGB2iR/d4UE2.TaOf.z.HKFdIlss/ds9EuzTLPkda9MYnuu'),
(1147, 'Kristin Elso', 'kristin.elso97@test.com', 'invitado', '$2y$10$XhckAq8BYFXWY/8vZMe/meXy5Vr6UgbeOIQ6p89gT8LKbBNQ3cyCa'),
(1148, 'Jezabella Busado', 'jezabella.busado249@test.com', 'invitado', '$2y$10$fQ7P5EmHsOEVDxa10fFZTuec29cKJ2ehG4KEnJdCbRUsLcNWrg0BO'),
(1149, 'Iker Segismundo', 'iker.segismundo98@test.com', 'admin', '$2y$10$QxgtCbYr4HozLB.eyRcU0OkDFA1WrNs51Hh9y8xjQ4kl7HsUNVLqG'),
(1150, 'Marcos Diosnelio', 'marcos.diosnelio250@test.com', 'invitado', '$2y$10$DcrWl.o0Mj7bQZAndNGWCeJhcjQlTRoH/cLKwgSRxnrT50BwuBJ4G'),
(1151, 'Diosnelio Tesifonte', 'diosnelio.tesifonte99@test.com', 'invitado', '$2y$10$lUNsCO10sLL3pduGIZR2YujD9dwEI0WWmY4.Y0flsTe6VHngSBhDW'),
(1152, 'Covadonga Aritz', 'covadonga.aritz251@test.com', 'estudiante', '$2y$10$zughT0Gn0Jiujyan2C4QKutJhWnqR8P/Ql1aRGvGPnn31EKbiTJha'),
(1153, 'Jezabella de la Paz', 'jezabella.de.la.paz100@test.com', 'invitado', '$2y$10$LoaGugmRv8vDrz7bUl.yluxAFDaAALr/edVUG5sCwk673TIdVa4S.'),
(1154, 'Bonifacio de la Marina', 'bonifacio.de.la.marina252@test.com', 'admin', '$2y$10$30qiygjp73HDAbznZKaExOlk2GuV928yddejPbvKQ1RG5cXoBEXVO'),
(1155, 'Sara Jurado', 'sara.jurado101@test.com', 'admin', '$2y$10$Cjirz4JtP5PsQYlbqgn0O.dnVHB3ZbGzihFYFw2jr5kTq0KrYCHha'),
(1156, 'Salomón Diezhandino', 'salomón.diezhandino253@test.com', 'invitado', '$2y$10$1rXREv0bqu6M5bZivnTTJ.mXaM1IdH5FaCmV11S/YVWbvMr2QoFOO'),
(1157, 'Penitencia Gordo', 'penitencia.gordo102@test.com', 'invitado', '$2y$10$kHKwDucJ5OK0A0HVSU6JbeTSNxO9c7XBWHzYndN.zpvE5RjMZUpbe'),
(1158, 'Leiona Calavera', 'leiona.calavera254@test.com', 'invitado', '$2y$10$raDd5uk4mbnQbUOClCIPUe6yQhZ6p0rzTjtZgT/RHqCLfWYWIQqD2'),
(1159, 'Gumersindo Lioncourt', 'gumersindo.lioncourt103@test.com', 'estudiante', '$2y$10$9GVtwWND2R0ld4KFsEYws.RYEBN5PqaePtFdMt/8sGh6XUU2Bxi2m'),
(1160, 'Georgina Pieplano', 'georgina.pieplano255@test.com', 'admin', '$2y$10$zVeBKRdegQd8.VPJ/yYnzuYzJy7IP1aKCA9C2njIcLRtpPib/v5xC'),
(1161, 'Iluminado de la Marina', 'iluminado.de.la.marina104@test.com', 'invitado', '$2y$10$OIuSJnUzcptMWhUTUYPqRu0QnSetTG7m1MNFbcVF02s3CEX7p5tg.'),
(1162, 'John Mingo', 'john.mingo256@test.com', 'admin', '$2y$10$ipqOEnbvV6Tu6aBNVlkupudpH03J27eCWiEud.fD2bOmX3wA3c.BG'),
(1163, 'Aritz Ladrón', 'aritz.ladrón105@test.com', 'admin', '$2y$10$HtIGd7vIl3S.Ux.qpo6z7.Aixuj9HuGRfqjp5mXXOgwKp6lS3PHIq'),
(1164, 'Alba Zas', 'alba.zas257@test.com', 'invitado', '$2y$10$YTcZeGkTBNGmXZfh1P5cO.E6bXek1K2i7e7rOurvsFzqIsIGGnu92'),
(1165, 'Jerson Diosnelio', 'jerson.diosnelio106@test.com', 'admin', '$2y$10$xaKjgyV/yxE9aFjtoRDIoOm9WEs./gblCORYdjrLbHxjf1.i2wGQ.'),
(1166, 'Samuel Pieplano', 'samuel.pieplano258@test.com', 'admin', '$2y$10$vevJAoy7PukRIL3Vq3jw2eKVtYcQpAZwJeipLwoF4M9ETvxd2dyQS'),
(1167, 'Sara Burgundófora', 'sara.burgundófora107@test.com', 'invitado', '$2y$10$o.hW/FwBQVoVYLSx5KjJ5OGYw/AB7ElamlAxKnHGKV/Tq6dAU/t7q'),
(1168, 'Drac Sandro', 'drac.sandro259@test.com', 'admin', '$2y$10$rDSx0kQgY7K6KDPi6NELoOQyLUlWHdLAfIiJH8EB4fn0EH1ZJW34.'),
(1169, 'Gumersindo Busado', 'gumersindo.busado108@test.com', 'estudiante', '$2y$10$/ycCjIsaXoaLhKC5hTPlPu4ZHyqs.6c6Ov3HXgRkZnfb088ddG3wK'),
(1170, 'Edurne Iluminado', 'edurne.iluminado260@test.com', 'admin', '$2y$10$MWi871z8n.e5InVMfpWLV.sP37cunERZTu5EzZiFl9vDtOvXk/DPa'),
(1171, 'Yoringel de la Repolla', 'yoringel.de.la.repolla109@test.com', 'admin', '$2y$10$5zmh7bnnE4LxF.twQWRQRubDy2chplj.dvan6tzkBMjJDHZgSpmvW'),
(1172, 'Jorge Moto', 'jorge.moto261@test.com', 'invitado', '$2y$10$974LP8gRiNFvEhWtYBIGQ.4a34MoDxQMbMDpUf0yvkx0oH9ShFiQ.'),
(1173, 'Eire Apolinario', 'eire.apolinario110@test.com', 'invitado', '$2y$10$j01Akdj/i77lRdEdjaZsEeFZ8otWckfZ86iz9RL6GkFe4tP9zE6x.'),
(1174, 'Renee Silvo', 'renee.silvo262@test.com', 'estudiante', '$2y$10$qOPzPZAAKrAN/bvvyWhcAuAWgQ/v78DJXCkFPY7f1uO8USezhP7Zm'),
(1175, 'Eros Cortada', 'eros.cortada111@test.com', 'admin', '$2y$10$OohoCBYLNapPAvFJbuh5cu1iiNwIWcsiG3xbWJvFYmNAa7bk8sxEC'),
(1176, 'Sara de la Marina', 'sara.de.la.marina263@test.com', 'admin', '$2y$10$wEuLsunENqZZUBiN1Zy7fuTPsFSkpbOoRYe//2xZgagefGKkf29sa'),
(1177, 'Eros Fina', 'eros.fina112@test.com', 'invitado', '$2y$10$yIE3///e7yAJ0VW6X2pb9uFl49jEX7F246TsSVv0s3jr8iHcv7HM6'),
(1178, 'Ana Irantzu', 'ana.irantzu264@test.com', 'estudiante', '$2y$10$IVPNFF30BL3pQ.LftNlxYOOutDC78KYH7ZnnFyO8wHeZCJGOz/STe'),
(1179, 'Froilana Delano', 'froilana.delano113@test.com', 'estudiante', '$2y$10$rgUtbOiUhevrynF6LBUZMekOnjKBCyfUhN6IuPm993FO6t2VFz6aW'),
(1180, 'Eros Marciana', 'eros.marciana265@test.com', 'invitado', '$2y$10$IA.2HVFW794gbTUZwad2nuTaui6E0tR9nKUXlBUl/40FFKxZvu2Ba'),
(1181, 'Louis Aritz', 'louis.aritz114@test.com', 'invitado', '$2y$10$yF6JLalomFm9nW3OnCIYdOATVo209GWP2MBx6YuAUwmkqN70gcbtK'),
(1182, 'Eros del Carmen', 'eros.del.carmen266@test.com', 'invitado', '$2y$10$AtfhJs0VTe5sc0SSIHilr.oxmlAzqtQ1Bqt7i/rErfsXdEaGU0PCi'),
(1183, 'Patxi Alegre', 'patxi.alegre115@test.com', 'admin', '$2y$10$.LdUQpHMcsG04d8jiUPjAeVYnt7var5q0tjvsqMJb70Z5htpeeUjC'),
(1184, 'Peter Artemisa', 'peter.artemisa267@test.com', 'invitado', '$2y$10$bwU.29YsumAY7oeUdS7ihuOgmsyFtxZW8bs99YOgQFeaOMpm3OfJS'),
(1185, 'Elba Calavera', 'elba.calavera116@test.com', 'invitado', '$2y$10$JinUUsHnRkSogU9HA7.MG.uGT84a1vLHZJ9Nfo/gJ1eiZR4NkEttW'),
(1186, 'Kristin Gil', 'kristin.gil268@test.com', 'invitado', '$2y$10$mwdXYUPn2.79ze9xOeiSUuLs/kT/eTemSutY9OpDdnIiUdnIJWokG'),
(1187, 'Andrea Martínez', 'andrea.martínez117@test.com', 'invitado', '$2y$10$CSSIqEUwAgtIbKJT2Gdet.RgbjGNqqTukparbiMHHHVP6fsMzIkL.'),
(1188, 'Elvira Bonachera', 'elvira.bonachera269@test.com', 'admin', '$2y$10$nZU9fnxr.5BXPuRMgADJquzFup.NTrVp.hQLyDCG5BIA5Q2VeDE4m'),
(1189, 'Zigor Gandula', 'zigor.gandula118@test.com', 'invitado', '$2y$10$hGq6J/JP62gxZGu7wPFdE.UmyTGoEkJS/9dshzHmCfEXcY9KpC9H6'),
(1190, 'Eire Valentino', 'eire.valentino270@test.com', 'admin', '$2y$10$zbWvkZWZWVwiUjCE0ZNcKe2zBxcRGea8IWTZYCTXqbM3oCBGNVoLu'),
(1191, 'Aaron Segura', 'aaron.segura119@test.com', 'admin', '$2y$10$A.f4HeULjMF8gXK5NaW71e8QzFeXRddA1Y9/4ps6ryPclKgoqdSam'),
(1192, 'Andrea Surero', 'andrea.surero271@test.com', 'admin', '$2y$10$jsZzgFH5825ZGy5AgZ/Coe5wRVRP44wzL6eZTR2XFDbpJO9EUSBNK'),
(1193, 'Enzo del Carmen', 'enzo.del.carmen120@test.com', 'invitado', '$2y$10$6huVc6cVrhptCDwcyu9ZHOY.upZHnfcVbeKjd1P51UdqodE49SqvS'),
(1194, 'Xavier Marciana', 'xavier.marciana272@test.com', 'estudiante', '$2y$10$3cg03oyF5b93tx2e7Fvc0OJtwNiqQgrbzeVnlifTd4IBStQ6Bzi7q'),
(1195, 'Argi Botelli', 'argi.botelli121@test.com', 'estudiante', '$2y$10$z3EE/8AI.FtjggSuN.6kJ.GZEr9nfEkHhWOTlt4WoFTbl1fdPr4ZC'),
(1196, 'Luzdivino Ladislao', 'luzdivino.ladislao273@test.com', 'invitado', '$2y$10$5efXZO.t3/b8DP6kacxQYeeRJoVNDC8y1wr46K5AS5Vf.MXbdqCdC'),
(1197, 'Silvia Escolástico', 'silvia.escolástico122@test.com', 'admin', '$2y$10$EuLP981CiHtCsDtRwfICTesZ4U2cZt7UqhRaznFz7tHOb3b1NeWW.'),
(1198, 'Fulgencio Calavera', 'fulgencio.calavera274@test.com', 'estudiante', '$2y$10$OY/b7X588dUBdnufrHaT6.0oaQkbkWZeL253gxoTMx40c1dnw3eSy'),
(1199, 'Bojan Elba', 'bojan.elba123@test.com', 'estudiante', '$2y$10$CLZTOt3dlpV4SFeIW6AIOODSMpNyi1246tENNKkx6Q0OYdPTlRySm'),
(1200, 'Aitor del Bosque', 'aitor.del.bosque275@test.com', 'invitado', '$2y$10$xqtEPPT8WjIGMn7x406vy.aHslRkChMMazUZQ/cOSte5OEPBmW1sq'),
(1201, 'Raúl del Bosque', 'raúl.del.bosque124@test.com', 'invitado', '$2y$10$W/pNLyQMas7yHboRZ8nvWe2wcDvwCfpkG2dxqzHboCfe5cldR3i8y'),
(1202, 'Antonio Bojan', 'antonio.bojan276@test.com', 'estudiante', '$2y$10$wPZ7/wv6omopNzQ79jSMYeZLZA3E0N08htWws7wA.KMRjCxSPMLp2'),
(1203, 'Penitencia de Covadonga', 'penitencia.de.covadonga125@test.com', 'invitado', '$2y$10$F9u7ajSHwy1zJXX5Pz2joucursEzlDFc79fXLSk4HHx8tdfvTYNPm'),
(1204, 'Amadora Segismundo', 'amadora.segismundo277@test.com', 'invitado', '$2y$10$tTTcr1bPfw.lQ6OKfBYBoekdWuRXN6Epj0gFXnhzst4qoR8xkjzze'),
(1205, 'Eire de Dios', 'eire.de.dios126@test.com', 'estudiante', '$2y$10$U9t6uc72Ijaext7s01/SzOEpBICdN63gNWOf6zlDFf1zYUbtAIlxq'),
(1206, 'Elba de la Vega', 'elba.de.la.vega278@test.com', 'invitado', '$2y$10$jwexCd7QNRfDsWmruUgNz.oz5eDAOAEcG1SXnJosy5XLK23QfjWUm'),
(1207, 'Fulgencia Paramí', 'fulgencia.paramí127@test.com', 'estudiante', '$2y$10$K7lgjNIv6UVL6gETeGWDmu23bYSProEgFZjhPX2eFOOqqPABHwme6'),
(1208, 'Bojan Fermin', 'bojan.fermin279@test.com', 'estudiante', '$2y$10$8BRWSEWHaT4AJaA7kHLgn.F0bE4TspZ15OQh9nDkaEKa7EiH0kXaq'),
(1209, 'Laia Gil', 'laia.gil128@test.com', 'invitado', '$2y$10$N2o.nLZ.oQI7YpXlvZ7puO5G5s15oDNKbu9nbtBrP4s7rOnGhBgT2'),
(1210, 'Samuel Cipriniano', 'samuel.cipriniano280@test.com', 'admin', '$2y$10$LW0Vl8DhFzM7RQ1vbj5Ev.b00TUcrEJa1yzmkb2LCO5VqbqaB.gEK'),
(1211, 'Elba Masdeu', 'elba.masdeu129@test.com', 'invitado', '$2y$10$788uqUKhkMZu2/eaVBZoeu6RioxbVizmWDeTfwsdYID4SGK06vHmG'),
(1212, 'Alejandro Arnulfo', 'alejandro.arnulfo281@test.com', 'admin', '$2y$10$ZXlPQq75QrKniaS8WmS27u8ZtyW0wEh/in4qFyF3SnuJMjO85h6f.'),
(1213, 'Jano, Elian Gumersindo', 'jano,.elian.gumersindo130@test.com', 'estudiante', '$2y$10$XmLVu9lpoSaaP0gx0VX4FOMaWWLI7Th87Y/wt7EQKlAnI8KvBFtFC'),
(1214, 'Enzo Díaz', 'enzo.díaz282@test.com', 'estudiante', '$2y$10$FhiFK5021kp.Qv6ocHM8DeIyFIBCO6b.PCC/KjFRKtzUcHvNCKdZO'),
(1215, 'Marina Dombina', 'marina.dombina131@test.com', 'invitado', '$2y$10$phqmDrsATde/5dFmbUf5YOOqCBlfTCQeHsNEc9wUa.giYVshdwAda'),
(1216, 'Diana Parahoy', 'diana.parahoy283@test.com', 'admin', '$2y$10$bMYUqLttsIBzyekLD4iJKuoBp19wT.Pk64rFoJI86Lnkhy3/V2tRS'),
(1217, 'Eros Kermit', 'eros.kermit132@test.com', 'estudiante', '$2y$10$y0gaDdl/aBqZ1JKXncgIEuWkcexJf18UhNYe/eranWBedMCvWi1aC'),
(1218, 'Fermin de la Vega', 'fermin.de.la.vega284@test.com', 'invitado', '$2y$10$ZHzaRatAmFE63NhXl8/kEefdT9MIEcb8U21cU2XtkutWVXqs.ORkC'),
(1219, 'Elvira Alyona', 'elvira.alyona133@test.com', 'invitado', '$2y$10$xeksuUZkFb3mslHd86HQI.9YSM4u19l5ZByNO8i96M88NugFWwWuy'),
(1220, 'Otto Artemisa', 'otto.artemisa285@test.com', 'estudiante', '$2y$10$uOD81QHMkvCUd9oXX2Qk6uULeMrDDGBdsSWXmfmZqsxOBTgo.ty/e'),
(1221, 'Hierónides Hierónides', 'hierónides.hierónides134@test.com', 'invitado', '$2y$10$Y1S/W8zJ5Zd1aNVEy5DEyeIS1hfGn7hTkYsKgszruYec0gEGLmufC'),
(1222, 'Marina Salido', 'marina.salido286@test.com', 'estudiante', '$2y$10$THVusgj0Mx1VEF1Vx0pTmuw0MueY/KKuAeNbrWMk3QnnwzxsNYVDO'),
(1223, 'Leiona Diogenes', 'leiona.diogenes135@test.com', 'admin', '$2y$10$ZAdiqmmfJ8sHX9VPP5sE2.3uTocAZQbCrsUX8nZRk1mYvvGDG1pv2'),
(1224, 'Nick Dombina', 'nick.dombina287@test.com', 'invitado', '$2y$10$VRu.tf.RXZ88sA8m4gnrp.BJCnm.SDuew3w9VC0E1jxG/4XrdcT7G'),
(1225, 'Renee Elba', 'renee.elba136@test.com', 'estudiante', '$2y$10$eUBxMkO3d6HxvaLmjUoybOqvmbV5S0FIka1wHEP1mbpFIsPMnxnK2'),
(1226, 'Estanislada Ladislao', 'estanislada.ladislao288@test.com', 'invitado', '$2y$10$RZE7.H9QtFYR9AqTvSFlBu5PfGFx8PFSF2IeyMls0P9qF2rfZkhha'),
(1227, 'Miles Dhu', 'miles.dhu137@test.com', 'admin', '$2y$10$uE/eA/jNylty24FwajMYR.U68PIuiejUgRltt7OTFxQO6t9z7KNYu'),
(1228, 'Elvira Esario', 'elvira.esario289@test.com', 'estudiante', '$2y$10$D0M9vFspB3rtj72Z35bwjOkH/oEaJ.CHhMwwllBB/6K.domOqUr6G'),
(1229, 'Elso Protasio', 'elso.protasio138@test.com', 'invitado', '$2y$10$o.FJuegKiIrxdKZYvcde3e8e/U5PEc8GYY.hD9cyg/W5JFP8Hr0.C'),
(1230, 'John Elso', 'john.elso290@test.com', 'admin', '$2y$10$LHGl4Rp4kl4b9mCUfnFiaeOs7U9lc7bjVm4WmvCZEZJ7Bzy6tC1c2'),
(1231, 'Pere Pantaleón', 'pere.pantaleón139@test.com', 'admin', '$2y$10$CDlCDy/ewkRKTZp4jOeYuOBQTD/SZJxlZiz1bx1pEoOJ0Os1fvvQq'),
(1232, 'Iluminado Apolinario', 'iluminado.apolinario291@test.com', 'estudiante', '$2y$10$YKAI.Q4JNn3xm07/IC3xSewsq3U26heowzuuauH9hGGT.9Opw5qS6'),
(1233, 'Ana Pantaleona', 'ana.pantaleona140@test.com', 'admin', '$2y$10$lr.qipLpQz6SVLHFs8U9v.YtMfsgsWlT3TTkN7cftpxDfMmJA8aku'),
(1234, 'Elso Elba', 'elso.elba292@test.com', 'admin', '$2y$10$WIbaUhkVsCu1yWa0nBetUeV2CxBYT8WHcGxTzREKmLkL053jCYGQO'),
(1235, 'Sergio Patel', 'sergio.patel141@test.com', 'invitado', '$2y$10$2DwLQxpnGcqVRpocR/J0iOFzhYkCVlDu5t0XFhfN0woCiEshlLheO'),
(1236, 'Alba Pieldelobo', 'alba.pieldelobo293@test.com', 'admin', '$2y$10$WHdIkBcM1lUnNm6vGeF0UOYYrkMYCy31OLn39re1RvqbGMG6ErU5K'),
(1237, 'Marcial Tesifonte', 'marcial.tesifonte142@test.com', 'invitado', '$2y$10$.uCVrHYQgnHym/k9fYZFwOjZi5SXDiFxCBTn3w/e/rXvfRAuaOkee'),
(1238, 'Mercé Sánchez', 'mercé.sánchez294@test.com', 'estudiante', '$2y$10$ZvyfLuS.g2YOBfoLi9JrHu/PLveBAzsdgDfjqT4ByaPvaMZ/T3QqS'),
(1239, 'Obdulia Sandro', 'obdulia.sandro143@test.com', 'admin', '$2y$10$FD132t9exeoDLavQ6iObce/CNod5UUYUnO3bqrNrm3GdNaPyPIFva'),
(1240, 'Marc Alcoholado', 'marc.alcoholado295@test.com', 'admin', '$2y$10$RojYXJOnj5gMwwfbd.MQOeBIKXobUdCdOpAb7EWvHIjwnTrTATolC'),
(1241, 'Lidia Osario', 'lidia.osario144@test.com', 'invitado', '$2y$10$Duzbd9cZ4.9cNiWy6fpknufwL3sgr2ZrSbC7/bgdGdxISVEEmdl1a'),
(1242, 'Guifré Artemisa', 'guifré.artemisa296@test.com', 'invitado', '$2y$10$Msnv3daLt1Y0TVMdiClElOybtVh8a5UPrlTOHFWSV8.ixQJ9LvyCO'),
(1243, 'Pantaleona Cortada', 'pantaleona.cortada145@test.com', 'estudiante', '$2y$10$JyR2Btfrlib2EkEx/8dY1.CVWXTVq0ezq1WSxRZI9k/qU1lc8k/py'),
(1244, 'Dolores de Barriga', 'dolores.de.barriga297@test.com', 'admin', '$2y$10$5GbYkqPFpW.25jT37m/hWebye2.wMQ0EDesOTMh3uRZAz7zMDv9/6'),
(1245, 'Renata Sandro', 'renata.sandro146@test.com', 'invitado', '$2y$10$nTRvDVlMZPS5tnIdsaAnROLmixfKdvZ0KCijR7UWeh4MCRUurw0kq'),
(1246, 'Raúl Moto', 'raúl.moto298@test.com', 'estudiante', '$2y$10$UMf.M5D.YGRSZW.krS7slOGniwkNTsDSRBP1oD9gBvHHKWZyUWCwG'),
(1247, 'Elba Zas', 'elba.zas147@test.com', 'estudiante', '$2y$10$UtRaacPdv9rn.eUwSyhdyO.q3Rygno1XwYBD/8uZcos9GHZsdMwam'),
(1248, 'Diosnelio Gumersindo', 'diosnelio.gumersindo299@test.com', 'invitado', '$2y$10$aM0QyC29X/Qj3rTZeFyKqussRNEZdrW3ujQLSiY6bdAZcJCc93ny.'),
(1249, 'Cipriniano Dhu', 'cipriniano.dhu148@test.com', 'estudiante', '$2y$10$vFGQTLn1HEkgZQ7.JllMeeBwJMNPFYI0mnQzGsfIoQAimYefxLb9.'),
(1250, 'Elba Dhu', 'elba.dhu149@test.com', 'estudiante', '$2y$10$NtDWz32FMLvr7g2AW2YC8Opz0LPzST61jCAEI09MuJMvSqKVUbfT.'),
(1251, 'Anne Verdugo', 'anne.verdugo150@test.com', 'estudiante', '$2y$10$YUT3KoDaRKwzvpRC6yvaguqqTZnr0mvWZokXpZpAcRKV9nTuD6HZm'),
(1252, 'Dolores Alcoholado', 'dolores.alcoholado151@test.com', 'admin', '$2y$10$JRJAJ0aciCLvTAq3Zq3SV.OjmztISwDldxdAIvnZXwdxGKapYhGPq'),
(1253, 'Abba Apolinario', 'abba.apolinario152@test.com', 'invitado', '$2y$10$DTp9DHEtGNPQRQE7vG5wd.KlfZbIq5psdbbL0dWAWrBgFqEg42coq'),
(1254, 'Iluminado Pérez', 'iluminado.pérez153@test.com', 'invitado', '$2y$10$O6wqWHKKMOtQHCWVVhdwE.KFPtAKssaGzR1fQeV.rRqPNXzepSjFq'),
(1255, 'Covadonga del Rosal', 'covadonga.del.rosal154@test.com', 'admin', '$2y$10$RzeWsHMIs7gXSS1oS01dMeou44pzB2nYqH4qTlHKLSAfH7o5kQBwO'),
(1256, 'Rúben Japón', 'rúben.japón155@test.com', 'invitado', '$2y$10$Z80T92cCoY3X3g96lDIqIuVjOEzjcaYim.aDMkSWbC/Ou3qZlKevy'),
(1257, 'Arsenio Gil', 'arsenio.gil156@test.com', 'estudiante', '$2y$10$M5FZWPSykIO.5.xKRNiLDe5BaMqE9IJFmO49AmEg3ItFsAezdvq4i'),
(1258, 'Pedro Albar', 'pedro.albar157@test.com', 'admin', '$2y$10$DUmN/3FqMKnRWrWSNFkfQ.OJ5ULpudVl9hS6X6KXuKcY6UDVVT7lO'),
(1259, 'Alyona Iluminado', 'alyona.iluminado158@test.com', 'admin', '$2y$10$wLF6jDrpxs7.6BJIvVQkze40AynknxYuBa/2rjRhY6zHAARUjtuVK'),
(1260, 'Eneko Alyona', 'eneko.alyona159@test.com', 'admin', '$2y$10$O17P2J6NzXKKF9TmrrSPze7eo3xFYHIq7V7rlcUHI1z.PW5e4gpMC'),
(1261, 'Burgundófora Salido', 'burgundófora.salido160@test.com', 'invitado', '$2y$10$2aCPBwWwF3nmtb2UeLLRdeYSVBgp0CdNidfBW3fL8R5gFz9MOUcRO'),
(1262, 'Montse Marcial', 'montse.marcial161@test.com', 'admin', '$2y$10$9UI8G/I3ZExsQMiThB39O.7s0tXH9UM.ysuj/Fpp0pMKVcxn0vNuW'),
(1263, 'Andrea Honrado', 'andrea.honrado162@test.com', 'admin', '$2y$10$j8ECvILUHEL6qcpb4VZKGO2Z.7EAQEsPVdNMNrWXjp.NSDSGneGeG'),
(1264, 'Aitor Bronca', 'aitor.bronca163@test.com', 'invitado', '$2y$10$GBDCvnoX2j8YdIkbKYG.peSMYnPtCM/gJKDVAH7zz4w7ZXHcp8rxO'),
(1265, 'Estanislada Kermit', 'estanislada.kermit164@test.com', 'invitado', '$2y$10$AmihucRrAkIFzm.PVnbdvuAHj0ihG9cSPdUlH7UIeOI6svj7wfDyO'),
(1266, 'Valentina Miles', 'valentina.miles165@test.com', 'invitado', '$2y$10$KsZgABWeF/jmFH56WecTHOq7Ys8.banyxh4NdK1LQOlfrQtMFYT2C'),
(1267, 'Sandro Alegre', 'sandro.alegre166@test.com', 'estudiante', '$2y$10$yhFVVyxLRKe0J6ugaZi/GOt0yu1q72eh5c6tjM7oTkbwJbLD9bMIi'),
(1268, 'Gumersindo Iluminado', 'gumersindo.iluminado167@test.com', 'admin', '$2y$10$ISHwZMQx5412RH3zYAzAL.awzDr8AlOC/Bd8ufiBfziK708sXLV0q'),
(1269, 'Argi Fermin', 'argi.fermin168@test.com', 'admin', '$2y$10$2YcCcpni9xakMPJe6DI5.OsWGft1vEL8OOON/ixOrGkaTXXw7P5tW'),
(1270, 'Louis Paramí', 'louis.paramí169@test.com', 'invitado', '$2y$10$Z2rFi56BcPapl6CdylafmeDoadf68HL746PKoNh1iIrCUiqwEl3.u'),
(1271, 'Jorge Silvo', 'jorge.silvo170@test.com', 'invitado', '$2y$10$FT5mLULfAmQWLX2MCKERuup7YuBkPyNzzL1gsAT9gBx1sAilP7/2a'),
(1272, 'Burgundófora Iluminado', 'burgundófora.iluminado171@test.com', 'estudiante', '$2y$10$La9Oo4UblebBSFVLWgStbu2Kl1VTuUDq1VGxl5osfF2Gsm8wi1SaG'),
(1273, 'Alejandro Pieldelobo', 'alejandro.pieldelobo172@test.com', 'estudiante', '$2y$10$sTqrl84id4Zt5l0GsIeJpOTHbWlV.hwQdrKPj.joygIrxj2wYWjzq'),
(1274, 'Leo Kermit', 'leo.kermit173@test.com', 'admin', '$2y$10$1xQt7Sstmz5MV2LwzEswXuCIm8GTlNP7LI6AoOmAC5U1XDTkKgwFW'),
(1275, 'Diana Yoringel', 'diana.yoringel174@test.com', 'admin', '$2y$10$L33OL.ArRat48uGJeBBo3OUkWjYxbKYh5K66UZhRQCddE1MJjdeGu'),
(1276, 'Patxi Gómez', 'patxi.gómez175@test.com', 'estudiante', '$2y$10$C1B4uSfTJOXadW9cqxGGDe8LLDCzA5gQg51XXLGb.KMaZI3J5IwGK'),
(1277, 'Ezequiel Silvo', 'ezequiel.silvo176@test.com', 'estudiante', '$2y$10$cuXa01GtNTvlJSoZieuOrOuawIBUTLqWjANEOMTakmLvTlvBEE.CG'),
(1278, 'Yorinda Alegre', 'yorinda.alegre177@test.com', 'admin', '$2y$10$SVsuCTJU5axoqd2oHEyWn.y8tDRro0hNXaOZlMPAr6WEivMavukha'),
(1279, 'Nicolas Alyona', 'nicolas.alyona178@test.com', 'invitado', '$2y$10$VaSUiTIKr9HdbQ1X9kFVN.jm/ge0Pqu4tuShxJutpAX2leoYPTAxC'),
(1280, 'Armando Tesifonte', 'armando.tesifonte179@test.com', 'estudiante', '$2y$10$nLdN6tH/HsGTDlphs.zrx.uyfKt4R/YKtwRQDrNRiBDGK64HK3guS'),
(1281, 'Leiona de Barriga', 'leiona.de.barriga180@test.com', 'admin', '$2y$10$K87byQwIAqLwvceUJdWRAeUaXj9DKQ068aeo02.ZwUWwYdSK4GzrK'),
(1282, 'Bonifacio Fermin', 'bonifacio.fermin181@test.com', 'admin', '$2y$10$IDmTmyBuO809EjJRPSS1muxdKDY7Y9Mxs0rlxqxYtxAG3G5vonuYe'),
(1283, 'Milos Fina', 'milos.fina182@test.com', 'admin', '$2y$10$O1N0Ufphqn5lzX5dZLx2/.G9uagZhSNN41ELmuhv9lHtN.pMfs08e'),
(1284, 'Nacho Eire', 'nacho.eire183@test.com', 'invitado', '$2y$10$D1.7ZkWji3zqppEASVPRcOpLmt1peafAvIIHSDKs30F86oLoupvr.'),
(1285, 'Tesifonte Martínez', 'tesifonte.martínez184@test.com', 'admin', '$2y$10$c.3NGQrfjlXJaKQ7Df3aH.F/X4pVEj4KkE/DECHnzLYnfVGgrkJey'),
(1286, 'Vanesa Irantzu', 'vanesa.irantzu185@test.com', 'invitado', '$2y$10$LBNRkpMQR9G3W3Am7Q0sveAR5xESSXObzH40GSegDJx7RT6YiMwje'),
(1287, 'Uriel Digna', 'uriel.digna186@test.com', 'estudiante', '$2y$10$SfruLmN.hKNx8N6hxIvb5.AnUER5EgKe2Y4wN5zUS0494sF4wEZnS'),
(1288, 'Paula Osario', 'paula.osario187@test.com', 'estudiante', '$2y$10$d1vEifTaiU4XShqTNjeFU.Q5CwlcGddrV0xgIoifsF/jtv/1hICS6'),
(1289, 'Jofre Expiración', 'jofre.expiración188@test.com', 'estudiante', '$2y$10$y2Pz3pj5CeoW3NAsPUoH8.TE8wcTQxlYefP3qHd6PHKIKnyjr7ZCi'),
(1290, 'Elena Pantaleón', 'elena.pantaleón189@test.com', 'estudiante', '$2y$10$FB4EXGNW/kxm5Pbwc/lz7OtRcyl253NYA/q1ktuojw4xujGsOUS/W'),
(1291, 'Ana Mento', 'ana.mento190@test.com', 'invitado', '$2y$10$7kUYoSW0fBZflhE56lg4fuBiOoPJWXstkJfPPcxIwyMHWquD7HWhO'),
(1292, 'Aritz Pieldelobo', 'aritz.pieldelobo191@test.com', 'invitado', '$2y$10$PQ6YwGMqa/TLTkCV4W9dRub5Ppcqt8toTvTHLazlF2VUMKhOuH3HO'),
(1293, 'Enzo Hermógenes', 'enzo.hermógenes192@test.com', 'admin', '$2y$10$lukUf6Hs3/VBFOqwhZHvQOCax7tBd88.jRA./B6Md5zYykJIJgMiy'),
(1294, 'Patxi Botelli', 'patxi.botelli193@test.com', 'estudiante', '$2y$10$POG/yKCowDAwbOjaw6NmReyaCxjVHXL1S/XbyW77X6lxb8XwuKVf.'),
(1295, 'Piedrasantas Kermit', 'piedrasantas.kermit194@test.com', 'invitado', '$2y$10$wnBJMPzr.jD/6txne0w0xudor61mGcCC0B7jWl9GaYCPE2OWOjyUe'),
(1296, 'Covadonga Diogenes', 'covadonga.diogenes195@test.com', 'admin', '$2y$10$j7PN80lmF1RMgcQvUK7lrufAEELa/sMvsFiV6qJVivM1BAapusX1K'),
(1297, 'Iluminado Miles', 'iluminado.miles196@test.com', 'admin', '$2y$10$rUxfZGjEc2UnNJ5X2Z6oZe4MN5DP.y.pSuy14ORxqDUCwwyitKP/m'),
(1298, 'Lucía Gómez', 'lucía.gómez197@test.com', 'estudiante', '$2y$10$H7VvlvkgJfpsHRpegJ4.gO5I.0nbr9e4CoTnG..QHf0LY3wdKhA6.'),
(1299, 'Milos de Barriga', 'milos.de.barriga198@test.com', 'estudiante', '$2y$10$oZD8cU.tcMctMRg..Jfeh.OV.OaKm3GXurskXAzvDWXLoXc3IV5s6'),
(1300, 'Elso del Rosal', 'elso.del.rosal199@test.com', 'admin', '$2y$10$4XCUycb7jTwPgVT.SzyI1ORqO137/Vf0CbhCaze5RpKnuwOumzMd.'),
(1301, 'Eros Elba', 'eros.elba200@test.com', 'estudiante', '$2y$10$fpj/q5DhkKDGNXcInSZ2rOCq7Dp/tf.WfzAu8br0N4ModlLNdEoDi'),
(1302, 'Andrea Segismundo', 'andrea.segismundo201@test.com', 'estudiante', '$2y$10$vh6pj9PicX4ABfoaw6PfY.BZ3vDZWANAi5IxeAqVpLQ2R75VWhtlK'),
(1303, 'Isabel Burgundófora', 'isabel.burgundófora202@test.com', 'invitado', '$2y$10$Nyeb5OWN5XFsyvaUoAsnfeGO0ax8WW1Urv4PwpqRufm2PSpBMDgAi'),
(1304, 'Drac Bojan', 'drac.bojan203@test.com', 'invitado', '$2y$10$/6x2MNbxf3OzmZkBaZt05OgEQI9NdnOkDq8EDHlQofNpgmacZ3Kk.'),
(1305, 'Brais Jurado', 'brais.jurado204@test.com', 'invitado', '$2y$10$BBkTKiYsXl4/4A5mmxGcFuiOTbbvksRRVRSGsQjUQV1hLAB6ZuYdu'),
(1306, 'Nicolas Fina', 'nicolas.fina205@test.com', 'estudiante', '$2y$10$PcykVJ2xAKwZV6RscqZueuxT.dvORysGdbbqcxsjA/EGPTjWTFZ1a'),
(1307, 'Georgina Patel', 'georgina.patel206@test.com', 'invitado', '$2y$10$uw.7zl/0nNe6/QFpCQxOb.zdGZ8uQcJNZY8KZ96aRxJ/3DkdeP3V6'),
(1308, 'Blanca Cipriniano', 'blanca.cipriniano207@test.com', 'estudiante', '$2y$10$cfwqvrEH0OJGoEuzb1rhWev8kKuiZCbtM9FnQv6FUOaEKjjsQxYSK'),
(1309, 'Xaiba Irantzu', 'xaiba.irantzu208@test.com', 'estudiante', '$2y$10$uO8YKk2XVa7rWAaSKkwp7utu1juE0tMH4DJ.dOB1boTqT.R45deVu'),
(1310, 'Hierónides Gordo', 'hierónides.gordo209@test.com', 'estudiante', '$2y$10$1eN00ASdX2/XTCih7hUA9OTYzigDhXeBghcOyfmKmPskdAuMrA/i6'),
(1311, 'Montse Apolinario', 'montse.apolinario210@test.com', 'invitado', '$2y$10$ArYrzmYKFNVRj1KbkqGCoexHgTK3X9qdw7Rtt.xexoWIPrw8P0ZqC'),
(1312, 'Dolores Honrado', 'dolores.honrado211@test.com', 'invitado', '$2y$10$uwvvwrvIsJ0oKdapZU8pvefieY76MHBL7ZnCcPyQjFQgVcA/4h1RS'),
(1313, 'Piedrasantas Silvo', 'piedrasantas.silvo212@test.com', 'invitado', '$2y$10$A44zLYiqkcL.0pGueHKmjeJVi2pO2/8S2H5csPeVeawWmF5bkbdb.'),
(1314, 'Paula Honrado', 'paula.honrado213@test.com', 'invitado', '$2y$10$TSnS41hWdS8z9rU5CIRsku..KgQH/DsyzV7zLc4Qpk1JwuN3Ha6.q'),
(1315, 'Duncan de la Paz', 'duncan.de.la.paz214@test.com', 'admin', '$2y$10$th5FZZxNeV4F/itlSEx.cO2cnnFoJuKFv0bVEWyyCVStrQLC7qxMO'),
(1316, 'Luzdivino Cremento', 'luzdivino.cremento215@test.com', 'invitado', '$2y$10$i2kKNgftrau5RJVa7j5u0Oui/FNhTDzju52C70W3/9/C9kZRYSQPG'),
(1317, 'Jorge Bojan', 'jorge.bojan216@test.com', 'admin', '$2y$10$KIxqhgn4QM5laIBcS.3i/exTv7NpuS1QwW/rDQcZEF.94z1UQZiuK'),
(1318, 'Aitor Cortada', 'aitor.cortada217@test.com', 'admin', '$2y$10$3czyPEPZdmtfgu0oHaqnKeRBQxX.yu.321j9cSgyRfZt2rpDGRbPS'),
(1319, 'Mark Parahoy', 'mark.parahoy218@test.com', 'admin', '$2y$10$82wTLcq7Smj83jnslrJ1IuDGF/jwmz2tInA3bwDxjuepdXz7xrlfe'),
(1320, 'Mikel Artemisa', 'mikel.artemisa219@test.com', 'estudiante', '$2y$10$9MqKV.tZ.6E.YkGMiq65UeUykFTZCi12DTlyteAjfRUo.KQUqg56W'),
(1321, 'Penitencia Luzdivino', 'penitencia.luzdivino220@test.com', 'invitado', '$2y$10$WypJQDf8uV8YFB6gRXQ3ZudCMyMnIlnEznJjuNGWtKQRJyyXXWlDy'),
(1322, 'Gumersindo Mingo', 'gumersindo.mingo221@test.com', 'estudiante', '$2y$10$FwP2p9zCYZvwjb5ZTmc8gedFR7E/r9cS5IH/atR1hrfRWOdt1cgU2'),
(1323, 'Abba Bronca', 'abba.bronca222@test.com', 'estudiante', '$2y$10$lx9nKBRmm5tA5XNaa1stIufSuQkpqgreMF.ThnDGaK9tgKW55EeP.'),
(1324, 'Jofre López', 'jofre.lópez223@test.com', 'estudiante', '$2y$10$/t3B9LulUa6L1CUtA73H5uVKbSN8CK8kN4zLfgJIERZgCLuW6d6v2'),
(1325, 'Elena Apolinario', 'elena.apolinario224@test.com', 'invitado', '$2y$10$0WZDSwRow3ND3iTE0Xkyq.mRbejCiOBUDi.I6DwpUW4.hNQOH4Kt2'),
(1326, 'Marciana Piedrasantas', 'marciana.piedrasantas225@test.com', 'invitado', '$2y$10$1epd9T/08GSkQUs8TARyIuIrO.2dxnEhM8sTbJK25p48Gy3zrMv7y'),
(1327, 'Penitencia Díaz', 'penitencia.díaz226@test.com', 'invitado', '$2y$10$AOBnMlGXCa7ivLACVEAXQuwleEIugh1dshm9x3CckBzT5yUv8BwNi'),
(1328, 'Alexandra del Pozo', 'alexandra.del.pozo227@test.com', 'estudiante', '$2y$10$DCtzlPb.8Azpf.fpE8.6RurgD4i97VYL4L4qLbpSWz41BZqsxQO1q'),
(1329, 'Covadonga Jetson', 'covadonga.jetson228@test.com', 'admin', '$2y$10$uf3L8SlUltS7UdAzY7.Biu.zUy9oj9mbgM8uJoi1n5aKVrolVgYMm'),
(1330, 'Mikel Irantzu', 'mikel.irantzu229@test.com', 'invitado', '$2y$10$8mWSTc3E4gN7SnMmIkAXP.5beMdSDch9Z4vJi6OskTnFT9mvtsd56'),
(1331, 'David García', 'david.garcía230@test.com', 'invitado', '$2y$10$vcVnkAU4JftIO71dC6ZQV.ELZ8I.MFgseAmQF4ARNQB1awIwxI.za'),
(1332, 'Carlos Arnulfo', 'carlos.arnulfo231@test.com', 'estudiante', '$2y$10$r16z2N7.64NNb7d/.HlsBub4nNk4BM5uQuQt8oYQJB3wYxCuLkiGe'),
(1333, 'Vanesa Tesifonte', 'vanesa.tesifonte232@test.com', 'estudiante', '$2y$10$VJ1tfL.amCoDaZaHo6QS5e0jO3U2poMIJux30DbLEtE/SAG3pfCV.'),
(1334, 'Rúben Díaz', 'rúben.díaz233@test.com', 'admin', '$2y$10$vOxMKojOmQwMb2saC9XN1.Hm9vGuqaCrtJ7g0WCU/2ojjiN8iQKiC'),
(1335, 'Xavier Segismundo', 'xavier.segismundo234@test.com', 'admin', '$2y$10$PmEQ6QlMbxqcWz788wvv6.WkTZujKpgVGsoL09GiI182sb2BApQxG'),
(1336, 'Silvia Oristila', 'silvia.oristila235@test.com', 'admin', '$2y$10$TL5P00RBycv1XHCV4b79AuqliBEIgxrWehwM1FkpricBkDn00YnAm'),
(1337, 'Drac de Cabeza', 'drac.de.cabeza236@test.com', 'admin', '$2y$10$izT5LzKo19BCS7h9Txy3KOeTl7E0Dk.3TTha8Hd/HoPyR53aZTiSa'),
(1338, 'Nacho Gil', 'nacho.gil237@test.com', 'invitado', '$2y$10$Iz6IB.Bl7Ce7k0d0sQqrmeSo1A7Dpo0LyaNe5Rt1Pdu6VZ5WOwaka'),
(1339, 'Andrea Bojan', 'andrea.bojan238@test.com', 'estudiante', '$2y$10$75HqZ8GKlQvIBjuL4E0vmOUZ08LAKubXIXyIjg9ZLNtW5etb5tROC'),
(1340, 'Gemma Hermógenes', 'gemma.hermógenes239@test.com', 'estudiante', '$2y$10$4CwTIvKA0JR0MMVvWOHrMO0UaXZ6gQ9XHKGAetPB38xjP7ALkv502'),
(1341, 'Eire Tesifonte', 'eire.tesifonte240@test.com', 'invitado', '$2y$10$spSfA1LqtJRnNrna0.750Ob62ezCl3Y2rF1RAT.3qSIsXZLjMp84W'),
(1342, 'Lidia Calavera', 'lidia.calavera241@test.com', 'invitado', '$2y$10$Bz/f0hYsZ41gzP2zR8/qZuiqghoNIZNFCN9jPBhv6qjak036NDnZ2'),
(1343, 'Oier Diosnelio', 'oier.diosnelio242@test.com', 'admin', '$2y$10$jgUovpb5tprbzQg9y2z2J.HCfXzlGUZkSgNLnrs9DOiDdTojN0ooO'),
(1344, 'Hercules Marciana', 'hercules.marciana243@test.com', 'estudiante', '$2y$10$KYuCfdCLosa6hzyzU0kzROaa8GGmapUf3sMxPZN3axfsn/qrO1Aoy'),
(1345, 'Burgundófora Cipriniano', 'burgundófora.cipriniano244@test.com', 'estudiante', '$2y$10$A0mGAPyPhztHLHGQr1gvRei1BZPkTwgUjrvc8CG1UdYIxG8fIsV36'),
(1346, 'Ricard Bonachera', 'ricard.bonachera245@test.com', 'admin', '$2y$10$gPvfUPAhHhXQxZ7cehaOnOj4Fo86kMwHuHnFlvZ9eh9DemaHTDWlK'),
(1347, 'Dolores Dombina', 'dolores.dombina246@test.com', 'invitado', '$2y$10$AE/L/uulTQ5SkY9jUJhI..jL/xj3q1SG4Lyc01.3HGJl1y9q/IX1a'),
(1348, 'Milos Díaz', 'milos.díaz247@test.com', 'invitado', '$2y$10$Jg1n3wLuXQa1A.SG0TpKbe0aaHxnOOz58MjZV1/V7c4LEVOnKIEzG'),
(1349, 'Ben Paramí', 'ben.paramí248@test.com', 'admin', '$2y$10$SY1f27D63dKq0BMNWQxv1OnoVKwq5iazkasytxWUOOXUDYAjHJjJW'),
(1350, 'Laia Kermit', 'laia.kermit249@test.com', 'estudiante', '$2y$10$F./aDWoGRAs.hKKvvS56JemqncZNUnBpt4VmE2VWYI1CYoY.ez23a'),
(1351, 'Kristin Cuesta', 'kristin.cuesta250@test.com', 'invitado', '$2y$10$k5uaBowvAX38rZQExd.LZuvtzuPPysQAcTQRZTyTebIFmN8H446H.'),
(1352, 'Ruperta Gómez', 'ruperta.gómez251@test.com', 'admin', '$2y$10$MTyX7ydoow39MEvJ68w5a.kZljkrg0Mz.03qcZO85iuVwd00OWI6G'),
(1353, 'Abba Protasio', 'abba.protasio252@test.com', 'admin', '$2y$10$r7vGuH3rp3w.MvBVNnasvuHhglo.jWwluBbLVDM1OA0O8OCxdsfMC'),
(1354, 'Dombina Masdeu', 'dombina.masdeu253@test.com', 'invitado', '$2y$10$Ip0lpukhhhcW5OeVrJ.YGuunZzXpBfFVnOX/lp4HwS9yFjyiHVS6S'),
(1355, 'Diosnelio Tresado', 'diosnelio.tresado254@test.com', 'estudiante', '$2y$10$mQzbzQN8DDIy1UMWNGgdPuhaDk6gugYoCR3eR1xeCbn/wsrmO9zHq'),
(1356, 'Sara Gumersindo', 'sara.gumersindo255@test.com', 'invitado', '$2y$10$YNN7P.TjQYWXancdHA.vE.CgSn73JoSe9nAbOjvgVmGTHXZAqcfzG'),
(1357, 'Aitor de la Marina', 'aitor.de.la.marina256@test.com', 'estudiante', '$2y$10$HJBirt9Urkg.caC/nWUKtOvkze2RyF8WJNR5DnKh0bYGXgpoyGAKy'),
(1358, 'Yoringel Silvo', 'yoringel.silvo257@test.com', 'invitado', '$2y$10$hAVHHmrojogrLaBDooccG.1Lqb.5BkKnVChyVnll8IuZi2F4EYOzi'),
(1359, 'Louis Nito', 'louis.nito258@test.com', 'estudiante', '$2y$10$kUTwBNFahzBUqruZ.8fkOeG0mNkQAQvkG4rdWrFq54zdVdWM0c7rK'),
(1360, 'Valentina Artemisa', 'valentina.artemisa259@test.com', 'invitado', '$2y$10$QXU3Q0QbDeGwslJrAjxs0.6X0pfL.95Q7XagHnT.qNt/8NoHySjtC'),
(1361, 'Salomón López', 'salomón.lópez260@test.com', 'invitado', '$2y$10$uDdYSYn6qRywvn6qVlpHJOWLpMut2mzJ6H.cS.v6nCEH9BhvdRKEq'),
(1362, 'Enzo Burgundófora', 'enzo.burgundófora261@test.com', 'admin', '$2y$10$yjJJNJmSocQMZr2QHUX5xugb6j/xM3wJdzub41BYL6tsiCOPY17vm'),
(1363, 'Ladislao Yoringel', 'ladislao.yoringel262@test.com', 'admin', '$2y$10$KfbkKl2DCUg.rsI0efcQfuyakxybGKfJW6a0CgYil1nhyosGVxPla'),
(1364, 'Jano, Elian Nito', 'jano,.elian.nito263@test.com', 'estudiante', '$2y$10$uF8TZMSTD1D7EU3iLNnIe.NMync9.ge0lzivZTiqlsbY4UKF8HOky'),
(1365, 'Marc Silvo', 'marc.silvo264@test.com', 'invitado', '$2y$10$/fS9ReGtY.nucDzOzo7X/OLiuqGSQ3rNv/tTEcDqMdv1ZTgx3Yvb2'),
(1366, 'Jerson Lioncourt', 'jerson.lioncourt265@test.com', 'admin', '$2y$10$HfJmlbf9nSHLMoLh6uPLTeVCBAWJJtObOFBALOWmE.YdOM.PH.QyG'),
(1367, 'Bonifacio de la Penitencia', 'bonifacio.de.la.penitencia266@test.com', 'admin', '$2y$10$eX9pgpNh2gt0HcXWKwLJ7OMfoBnic3fHR4ylzedtY7TQz8rOAT7p6'),
(1368, 'Segismundo Cuesta', 'segismundo.cuesta267@test.com', 'admin', '$2y$10$MOx07nnncxAlQUkZqzw0QOi90TM1DqhHq4V5xa4GkPbVsNSCR7B02'),
(1369, 'Ezequiel Yorinda', 'ezequiel.yorinda268@test.com', 'estudiante', '$2y$10$pHuGWeCKhcGsCx8aXUvRR.CxtMhoIaamoQJ8ACy83ySGJafEfMt8e'),
(1370, 'Duncan Cipriniano', 'duncan.cipriniano269@test.com', 'admin', '$2y$10$AWbg35MmlDrk/h664ii7h.U62TAKUdx2o/ZaWeKZnI.1Km6C6Tztq'),
(1371, 'Renata Alegre', 'renata.alegre270@test.com', 'invitado', '$2y$10$.6kSfX2bBxn733n4oo4qzOjEvtKddd4NBM44xH7YuYRKqjeWFxk6K'),
(1372, 'Eire Valentino', 'eire.valentino271@test.com', 'estudiante', '$2y$10$TgPRoT2e7qjt091kjcsZe.6fMj7SbK4LkE2BWXxuqf9XPPeiqCSnm'),
(1373, 'Edurne Mingo', 'edurne.mingo272@test.com', 'admin', '$2y$10$TR/X/lXCIysQf1eUjzDpnOilGTbF7vAsYocS4pXyCrA0VMWS7OcjG'),
(1374, 'Obdulia Ruiz', 'obdulia.ruiz273@test.com', 'admin', '$2y$10$pr6NqLqDiMA2qulQIHP3Ieh9b9GShTo.cOOlVwYEmNqxjvhNk5jtm'),
(1375, 'Sandra Diezhandino', 'sandra.diezhandino274@test.com', 'admin', '$2y$10$h75ekWo/Q2wLJXfk8JO/XO/VgmEvxZGhcKD./tRjgurV6Nm/cC3a.'),
(1376, 'Abril Karamoko', 'abril.karamoko275@test.com', 'admin', '$2y$10$aLcTsi6DK.7ll6LQY/2ZXetNeouA84UUpJxtsOYXp52ri/Fizdld2'),
(1377, 'Laia Gol', 'laia.gol276@test.com', 'invitado', '$2y$10$VvUYHt6luO7Bt4hnCvy4QemzRJslHopriQh48GDkl1/wvOmvcviY.'),
(1378, 'Amadora Cuesta', 'amadora.cuesta277@test.com', 'admin', '$2y$10$u6GVC4cjSH8q9sGCK.O5f.pe7dGfRrfzBuZ3VpqhN0nZH7U6WB5S6'),
(1379, 'Duncan Cojoncio', 'duncan.cojoncio278@test.com', 'estudiante', '$2y$10$v4BPVEBaDr.57yd6z.PEou28sq8jhzi11yS/204fjUkZLPLeBSWfy'),
(1380, 'Froilán Albar', 'froilán.albar279@test.com', 'admin', '$2y$10$E78Rgv18/eLwZvfVG3Xm7OQvxhVJbPPSAw.66WTQ3ctk81j8RNUSW'),
(1381, 'Marcial Elsa', 'marcial.elsa280@test.com', 'admin', '$2y$10$pAD8tS2Nij14Qrijykr/ruUkilPpOHNrCsFUX3GGeBuZS/VfARoA6'),
(1382, 'Diogenes Alyona', 'diogenes.alyona281@test.com', 'invitado', '$2y$10$ENuBev9ALYEJDYx8.L1N..qfyG1JkkU.RWvIooPVtZRQzhfbr6WUO'),
(1383, 'Paz Elba', 'paz.elba282@test.com', 'estudiante', '$2y$10$USy6xci8ycNhOS1.NrKofeY6N3a445iheDCFigsOUHfY3edGITtWC'),
(1384, 'Amadora Arnulfo', 'amadora.arnulfo283@test.com', 'estudiante', '$2y$10$0FI.9BUyomvn/GUN5hWHCO36y5m61c3sETZzbMflQ9pDwAXWOLlBK'),
(1385, 'Arturo Arsenio', 'arturo.arsenio284@test.com', 'estudiante', '$2y$10$yPDqsCoGKXizW4v.YK6xRuQskcPCGRwoRqSgmMipLRkUJbcKDEUC2'),
(1386, 'Sara Gandula', 'sara.gandula285@test.com', 'invitado', '$2y$10$taLfq16VA.zOWK.App12LeHYuCfBhmnTAFH3ukilKP73aCLxo2mx.'),
(1387, 'Louis Valentino', 'louis.valentino286@test.com', 'admin', '$2y$10$/c24CrnyXsBP4Ul/ZRLxCOin7ZWrLlDqsAR.BYb/N7038oiQnV83S'),
(1388, 'Nick Gil', 'nick.gil287@test.com', 'estudiante', '$2y$10$uC0kbx1HcsJt1Ch4X5wo.u2dpD78zthZMgMSbLtVKsGhEJQMz5PO2'),
(1389, 'Elm Cipriniano', 'elm.cipriniano288@test.com', 'invitado', '$2y$10$LLN19BY55PU4Z/PzQsQzl.qpSkjjr2k1LyiYvL014keDrXtVgsaCe'),
(1390, 'Vanesa Hierónides', 'vanesa.hierónides289@test.com', 'estudiante', '$2y$10$t3rL5cUBxeyqy4wxF4RVAOeeGBiRUC9AjubDagJ4HdpereylYu3sy'),
(1391, 'Andrés Cortada', 'andrés.cortada290@test.com', 'estudiante', '$2y$10$xPuNpR7PRHhDKIS5c9/8de7KyeS3dgdo1na0GWDJJFFQjVsDcnlAK'),
(1392, 'Ben Vergassola', 'ben.vergassola291@test.com', 'admin', '$2y$10$VhuB2Vaa3ga3oqN1vJEYx.JiZ6PWV1xE6BLSLYB5FyjHZa4GUYl06'),
(1393, 'Irantzu Sánchez', 'irantzu.sánchez292@test.com', 'invitado', '$2y$10$U4wUvBBx4qc6TWbUlnA7/uAvuPxN7dAMCDsK.R2QYkg4se39e1ldK'),
(1394, 'Ben Patel', 'ben.patel293@test.com', 'estudiante', '$2y$10$v3meQIRwzNX0eb5m.ffoF.HsZIBzIxhXq2FD.9ywSbLEfKeksGc/m'),
(1395, 'Marcial Kermit', 'marcial.kermit294@test.com', 'invitado', '$2y$10$/uDi23eLmFq5lAvg4nGEbOH2wJLqeUPYbu0p/szHd6s317VOjele2'),
(1396, 'Edurne Lioncourt', 'edurne.lioncourt295@test.com', 'admin', '$2y$10$ko5/85fuMZhIoOT1LQT0uOA5w93FOb3ubiQlINYQklkGw0XVO/OP2'),
(1397, 'Andrés Dombina', 'andrés.dombina296@test.com', 'estudiante', '$2y$10$rI4jd6e5iMKG5PEcR88mB.gEx4GmgtiNxrcskN70sFlT9F4sSJqFe'),
(1398, 'Fermin del Bosque', 'fermin.del.bosque297@test.com', 'estudiante', '$2y$10$zxhRrXED5IZAcpMDekgtQuySHqu1yGYSVTMa5Ygja0byKFPaKtOgW'),
(1399, 'Ana Tresado', 'ana.tresado298@test.com', 'admin', '$2y$10$YN52A4HTPZEU2fV0Yfsd7uQcvgvP.hzqwia9QfpD1N5mDX9sOShBq'),
(1400, 'Bojan Froilana', 'bojan.froilana299@test.com', 'admin', '$2y$10$gVTk95D8Xzcv1yUKYOWjCOF1F6cnEl.zgJPI9zxKFzswGV1B6gAtC'),
(1501, 'Yoringel Marchand', 'yoringel.marchand0@test.com', 'estudiante', '$2y$10$fJ9myKiRFNdXj1dK8LBEyOq4wP8vub7j2luChwaQcqirw8B6qARgy'),
(1502, 'Akihiro Faure', 'akihiro.faure1@test.com', 'admin', '$2y$10$iikh5T.k.H0Gl0kKsefPTu.KT5pwA16pPl6S3oUK4GBl8D4xNOUtu'),
(1503, 'Valentina Valentino', 'valentina.valentino2@test.com', 'estudiante', '$2y$10$T2wlgdUi5HdxtC/iVmyQPu7CZ93dhydDTnJ67b34o/j.2Pgv..C6C'),
(1504, 'Brais Amadora', 'brais.amadora3@test.com', 'admin', '$2y$10$5BaObRpuO7oxIRzrFK5Kl.Ep81sSRR5JVWa4eIfaXN/pbATf5LXB2'),
(1505, 'Hina Imagawa', 'hina.imagawa4@test.com', 'invitado', '$2y$10$3Y8RfZYlTH8eaQMuocl8a.ihBOZkfgHi64zJ7jjkuRS1FybBnfEEy'),
(1506, 'Uriel Iluminado', 'uriel.iluminado5@test.com', 'invitado', '$2y$10$xJl1PwaOOPelENt.DS7Ht.B0GbYs9Lx1lxreZTaBJKfwkAURRDO5K'),
(1507, 'Abba Nito', 'abba.nito6@test.com', 'estudiante', '$2y$10$irr/gWF4nxO0Bw81FPc.EOByfkPL1nqD42ora0g3if6Rv1E84jjqy'),
(1508, 'Nacho Gordo', 'nacho.gordo7@test.com', 'invitado', '$2y$10$eA2oQCIj48Oq6noKAihxv.iF68Op0zWAeP0Gn6VAN1gntdHr6irFK'),
(1509, 'Gabriel  Mihura', 'gabriel..mihura8@test.com', 'admin', '$2y$10$4qpOlNjmDOfWlPTfcVMdbept6e4Qyz.V6peza2FV2ZU8PpNsSqVwu'),
(1510, 'Luzdivino Armandez', 'luzdivino.armandez9@test.com', 'admin', '$2y$10$PV9D.EouXkChOqru1YXIlOxgkE6MdRiacGuRZ8o2IAvC2PQdVuxCy'),
(1511, 'Peter Busado', 'peter.busado10@test.com', 'admin', '$2y$10$9eKQ8ABq05k0l1JNlNnHfeoTvDfbRveOqNwEKuHXHgU5Nu1j4eKAK'),
(1512, 'Pantaleona Oda', 'pantaleona.oda11@test.com', 'invitado', '$2y$10$YGiJs6xtog5UyMIHXExcnOzJWjCmLo9RUFyLA/fObr3xfb6m4DIUG'),
(1513, 'Nacho Madarame', 'nacho.madarame12@test.com', 'invitado', '$2y$10$RrbTb/InAxFZsrxbXNx5v.CCbAJsLnRpJvsxt1deGJNJl57ygBM1C'),
(1514, 'Marcial Faure', 'marcial.faure13@test.com', 'admin', '$2y$10$hOn5eAGGROzVYWEuRw/J8Oc3jPryTS2R2hXs9e1p4o65gZNAFa95q'),
(1515, 'Daiki Escolástico', 'daiki.escolástico14@test.com', 'admin', '$2y$10$PgLyJRHXOUGvENbQa8AoV.WMmQYT5zcaPapSXZx0VdqyEIRuqPs4C'),
(1516, 'David Verdugo', 'david.verdugo15@test.com', 'admin', '$2y$10$FNkdiEmQo8TRvNXtBh8MKOlLOgYIqaRyxx3SElHdL7eKoUdnuzC56'),
(1517, 'Renee Marchand', 'renee.marchand16@test.com', 'admin', '$2y$10$DYfM9mhmDEW4TZEgd7XsUObsTrZEtfC8c56LqFmqj3VzTuMz8/68G'),
(1518, 'Hina Ruiz', 'hina.ruiz17@test.com', 'invitado', '$2y$10$vaevy3U9MT5Bb3Lp5mPcFuTTEwRoEBpJnnxVi2lzraQJe/tRVu2ka'),
(1519, 'Aki de la Repolla', 'aki.de.la.repolla18@test.com', 'estudiante', '$2y$10$2znbgdOdR7OiUHRcIr.C6OkvnDahHhA.LNthExIPoa7xm7Wud77XG'),
(1520, 'Robin Jurado', 'robin.jurado19@test.com', 'estudiante', '$2y$10$duZV/.b4lKthCIU7iyjUnudYOkxHlNMLpH12LmTKoF.IwP.Z/pCme'),
(1521, 'Eilán Iluminado', 'eilán.iluminado20@test.com', 'admin', '$2y$10$zygzhNoR.ZuZWIRY3l0BXunqmijkZSQEx.bToau38gpV4kwq2FPje'),
(1522, 'Kenshin Irantzu', 'kenshin.irantzu21@test.com', 'estudiante', '$2y$10$5LowlkVW4L./GmlOmj5yUeLVN7rApBarHqtaWMRddEUel9uxBWNne'),
(1523, 'Fulgencio Mogollón', 'fulgencio.mogollón22@test.com', 'admin', '$2y$10$KgFx/5FKsdsbUKPC6z0abuXDP8C72tQlN3fyn01dBHyP9BUX6Cik.'),
(1524, 'Georgina Tokugawa', 'georgina.tokugawa23@test.com', 'admin', '$2y$10$HlnykClMVpo1ETrF8fAn0.YvpVeibZyV1caIgpHnhsKjKXpksh2JK'),
(1525, 'Akihiro Colin', 'akihiro.colin24@test.com', 'estudiante', '$2y$10$kbm3eD3SsEyzVQSIPmhqgOR5yq4nAKlB37RNGirEYhBkbM.VbAZJ2'),
(1526, 'Elso Bonifacio', 'elso.bonifacio25@test.com', 'admin', '$2y$10$2PNeEUK0YTZBJHE0kakf2.XYMyacMurONsFPvB9LmwIyvz6BIkoZq'),
(1527, 'Diego Verdugo', 'diego.verdugo26@test.com', 'estudiante', '$2y$10$bwrnhkL7XGV4.giqgeY5KOEFWQdsmZFN4fN38vQIKHog/id9jUPwm'),
(1528, 'Luzdivino  Dupont', 'luzdivino..dupont27@test.com', 'estudiante', '$2y$10$yiLG6x5YoB84a0nyYwx4wu5QEQpUkHoqL.PiOwFMBYTMOs4SSf1lO'),
(1529, 'Daiki Leona', 'daiki.leona28@test.com', 'admin', '$2y$10$xFnNcmBtOQvgPg/ulpRkBuaHYHNI8wQj7SHVw.J89/PxbeGnC/oDu'),
(1530, 'Pantaleona Gol', 'pantaleona.gol29@test.com', 'estudiante', '$2y$10$74B3.sr05o8/E8bJS6WbvOE.Lkp3jyqMLZk5KSjw/tnp..NzHstgq'),
(1531, 'Ryu de Cabeza', 'ryu.de.cabeza30@test.com', 'admin', '$2y$10$jqs2C50RZ7YyCsyr2z5mm.dM8v13Dc0O8M35s8I7svMfP3WmxtgTO'),
(1532, 'Kaoru Patel', 'kaoru.patel31@test.com', 'invitado', '$2y$10$DSXCro89vrAoT6kN4nMBB.2kRQRHRrngXRpoM3UgnyzN7Cr9tPeOm'),
(1533, 'John Amor', 'john.amor32@test.com', 'admin', '$2y$10$j3H3JIg4qYDILGmrHvzNr.y/99TCAqKmbJUDhUE5tb9DoiApkKjT2'),
(1534, 'Andrés Arnulfo', 'andrés.arnulfo33@test.com', 'admin', '$2y$10$ddYYVGOPE3pP9y6O.zB.Ku2QOX0BNr0s441EVDF5pjhZ4WMZQCFyW'),
(1535, 'Marciana Kimura', 'marciana.kimura34@test.com', 'estudiante', '$2y$10$PHBD/2Ebe.iPgZSpZksz6.qvTHFEgVhGdRX2rxLiqRCdQZALUX1P2'),
(1536, 'Rin Lioncourt', 'rin.lioncourt35@test.com', 'estudiante', '$2y$10$UKLphFvJ.DGQB4PCyzj7sujFU5YI4q9HmHnwGSbtIBqQL0j.rVDwC'),
(1537, 'Hierónides Elba', 'hierónides.elba36@test.com', 'admin', '$2y$10$Jfi6ok6RH6M/4KBMAN9cEeZ6MjBIsh3EF7BpINsLvcGVQRiW0jxCi'),
(1538, 'Jorge Smith', 'jorge.smith37@test.com', 'estudiante', '$2y$10$F3yQOAXVX1tenJTLEGhkmuJmgSqv5NgD5TY5sKjBu1EvDPzdaKu9u'),
(1539, 'Charlotte Busado', 'charlotte.busado38@test.com', 'admin', '$2y$10$8bfHw2wLKaAYYcPx6a1B1OW6A.opsP2GYInEVUHzjfLR2VpWVQZXe'),
(1540, 'Martin Montada', 'martin.montada39@test.com', 'estudiante', '$2y$10$AclgUUCBSfMkggV607KMbeiq/fCLmlUIHYO5T0n7QKNewHXe.phzK'),
(1541, 'Eire Albar', 'eire.albar40@test.com', 'invitado', '$2y$10$txe7LO4pZelHR.eS9Jla0Ow3ZjtUoz9IQ9FqS/5hijzjMLds9hZAi'),
(1542, 'Robert Digna', 'robert.digna41@test.com', 'estudiante', '$2y$10$Y2v3xmmMyY6Q2D.8DNd6uuV2zTj.44clKys4F/qUkTQQBqAz4gu16'),
(1543, 'Hideyoshi Osario', 'hideyoshi.osario42@test.com', 'invitado', '$2y$10$LnfOwaq8ZJQwyrVwoI1m5ef51qZRXG9lEuCEPRDl7LyKP.f3J3iPm'),
(1544, 'Abril Arnulfo', 'abril.arnulfo43@test.com', 'admin', '$2y$10$UMCDXWgbulfsa.TAPAReheOWC5qqDfX5C1GNKPWiU3EwWXzN70QwO'),
(1545, 'Ryu Bernard', 'ryu.bernard44@test.com', 'admin', '$2y$10$YoCWSHaVuqBKza.IuKB2VeixLdy40ja2HlRRYRXEZuhBseSGg7yBe'),
(1546, 'Richard López', 'richard.lópez45@test.com', 'invitado', '$2y$10$uF6oq3mY6avQN8IBjNv.5uZRhLRPzzTSqhPIWVAO/BlzJLYA4kPDq'),
(1547, 'Duncan Dhu', 'duncan.dhu46@test.com', 'invitado', '$2y$10$M0.2tjQCYGZjwm12THQ5ouClP01hjTJ/bvJC41IKbCe5scA6ptpiO'),
(1548, 'Kristin Lioncourt', 'kristin.lioncourt47@test.com', 'admin', '$2y$10$dHsaN7CNTLZSAmJTjGSUrekAYD/Et5FgtIJ5UvVURMo.CNadVtM7a'),
(1549, 'Dubois Bonifacio', 'dubois.bonifacio48@test.com', 'invitado', '$2y$10$gkIsFvNa217vhQbYOd3Rl.VPDNKNaNTMYgeSP5zVjqORB6H7E5nw2'),
(1550, 'Hunter Amor', 'hunter.amor49@test.com', 'estudiante', '$2y$10$zXvpLURli9H959AowYccfOFWoHhiNEPt6Wb1j1hWdq68RXR4EHILS'),
(1551, 'Hierónides Pérez', 'hierónides.pérez50@test.com', 'estudiante', '$2y$10$vSfAoTNjyr//fWch09frGeTjRDmAEg5q.naMcT9UMTOgitkncdG9e'),
(1552, 'Eros  Mori', 'eros..mori51@test.com', 'estudiante', '$2y$10$AjnClhd7CKLGr3Vn1.0GY.qAg7rgAwNr2gkLDuK0CzHfoj4Xy9WZ6'),
(1553, 'Paula Brown', 'paula.brown52@test.com', 'estudiante', '$2y$10$cah7qLbEobqaZg8Xidb/PuqLYDqcV6ZQLaZz25cxUIs2wiFqsj6Z2'),
(1554, 'Luzdivino Tresado', 'luzdivino.tresado53@test.com', 'estudiante', '$2y$10$NgAUSlC1RoJqlzcrDT/SMejuwfBwIf/rsvr.OUQqtF2PJzscZ650i'),
(1555, 'Elba Hierónides', 'elba.hierónides54@test.com', 'admin', '$2y$10$hDGzRDJqoAqWGEZYf8.sCOJFNOxiWYedwQqQrOHnFyvgoUvXyoHzG'),
(1556, 'Chevalier Matsudaira', 'chevalier.matsudaira55@test.com', 'invitado', '$2y$10$jI4i9a8IkuPjQtxoT4/Ph.AuGU0vXd5RyaaY/2/ZweoMryJ4vU05i'),
(1557, 'Etsuko Esario', 'etsuko.esario56@test.com', 'invitado', '$2y$10$qxvVXLcdT2rJxp9xDyj7SOpPzNw8TqTGk8dFMuxECpWHK1FZ7JDam'),
(1558, 'Lucía Amor', 'lucía.amor57@test.com', 'estudiante', '$2y$10$tX7WKRJjr5NaMKymlYq5HO3fMAZaLiBCC0rd1haYIG1UTqMCUalIK'),
(1559, 'John García', 'john.garcía58@test.com', 'admin', '$2y$10$KFqfE1aDtrJDxzz6pXRGxufP30LktrO4sTAbzAsKqztzd1LWEGaBu'),
(1560, 'Elsa Alyona', 'elsa.alyona59@test.com', 'estudiante', '$2y$10$DEI5vttbjtYCEyQ.zuZ2ful/XM.1TJMTtETDC1vWCzWbv9XeV5BI.'),
(1561, 'Hierónides Oda', 'hierónides.oda60@test.com', 'admin', '$2y$10$gUeFMPZdD8D3TkDr8KCa6unHVWQjfD.BqHtqxJgqzz3TB8WJw/GH2'),
(1562, 'Sara Cojoncio', 'sara.cojoncio61@test.com', 'admin', '$2y$10$SBXmwXhuSQdmIjVaXxD7XeqfwGnpmHLjgDtkrc7cyLh6Vkz5QVePe'),
(1563, 'Nacho  Mihura', 'nacho..mihura62@test.com', 'admin', '$2y$10$Jp9RqiEg4EhxL0e6saJUa.bv6mJS2GFi6ERJmWgxpBbxEsXEHx3aK'),
(1564, 'Nick Arrimadas', 'nick.arrimadas63@test.com', 'estudiante', '$2y$10$f5ouKVc51HfJijtWayFJG.IC2j99hUVAg1J77addPV.bSLGEo94AW'),
(1565, 'Elena Fina', 'elena.fina64@test.com', 'admin', '$2y$10$gxHYtXYnelWrx.oV4W39O.SwWm7r6VjTXhzlsqXPZ3qdTzli/3Ite'),
(1566, 'Andrea Yamagawa', 'andrea.yamagawa65@test.com', 'invitado', '$2y$10$Fp8BMok8C35vU4tIUjqI5uxi4ycRPNc2X0jz68qmxfHU84BaN/QGC'),
(1567, 'Colin Yoringel', 'colin.yoringel66@test.com', 'estudiante', '$2y$10$Pf.na2Xxpk9bAxRkQ/wj1OcNVuvJgYKqg58oxFkY3VUvjrpaRhKPK'),
(1568, 'Jerson Toyotoma', 'jerson.toyotoma67@test.com', 'invitado', '$2y$10$SlMqqSefAcQtefIJ8Hfiqeuo5hpSeZ9frPdo1hKNnSoO2li0WcRfO'),
(1569, 'Rosa Busado', 'rosa.busado68@test.com', 'invitado', '$2y$10$oTS1EW0IHHaYI37nGa/YP.Kwb75ORiCZIBQbvT9s1jxbWCW9b1PGq'),
(1570, 'Elm Bernard', 'elm.bernard69@test.com', 'invitado', '$2y$10$.lFRPfuzE79Sp0vt.P8Xwup4V3yy0BoGNhZzkRERxuec5XBmmDgce'),
(1571, 'Akihiro Miles', 'akihiro.miles70@test.com', 'estudiante', '$2y$10$cq0UDLuQt922AjRe3JrCP.a6mg.Izo1tKHDxFeNSz//QQdaKbWELC'),
(1572, 'Duncan Alcoholado', 'duncan.alcoholado71@test.com', 'estudiante', '$2y$10$1wsobpir9c4dsEc5tTNJcuaLhzNlgHu4Q27DY9Q2M.1hmqgdrJnDq'),
(1573, 'Iria Cojoncio', 'iria.cojoncio72@test.com', 'invitado', '$2y$10$NkUH50rAfwgDKX/tyUZRt.U2FI08kyeGLj1GmNLFr1.U97LYNh0gy'),
(1574, 'Elm Fermizo', 'elm.fermizo73@test.com', 'estudiante', '$2y$10$6iLA4josHx5JzXm0y6J04eDQLeM4AdimcgMk3.Bdew3iVHBOfAZJO'),
(1575, 'Ieyasu Yoshida', 'ieyasu.yoshida74@test.com', 'estudiante', '$2y$10$/3x2NuPxXuXC9AeO93vfX.qMdKiWNQAWppUuPlHOB6ZZ.8u3z7YJ.');
INSERT INTO `usuarios` (`usuario_id`, `nombre`, `email`, `rol`, `contraseña`) VALUES
(1576, 'Akihiro Patel', 'akihiro.patel75@test.com', 'admin', '$2y$10$1nhWaww6XwlYRdRUQnH0L.tcstZaYFg78s9ZFWHBLl1ruRjYRt.7u'),
(1577, 'Madison Mathieu', 'madison.mathieu76@test.com', 'admin', '$2y$10$O4/SzGFM1XXULDAf4LFBsOHZFZC937q7laDohgrOJ6N63GweTXvsS'),
(1578, 'Blanchard Marciana', 'blanchard.marciana77@test.com', 'admin', '$2y$10$hNrl63jjoGo4KEYkyvRcUeQ9RwOzmRDi2qCEz5vk9jnT/2Lrp9ugi'),
(1579, 'Pantaleón Ishikawa', 'pantaleón.ishikawa78@test.com', 'admin', '$2y$10$iJp2qODeBTcMGDZxJA0RpuOWqpoT2jRJElZOUskvRj5YMiCRPKm3W'),
(1580, 'David del Bosque', 'david.del.bosque79@test.com', 'estudiante', '$2y$10$1VyyOxPXrVHMuCPya0kVB./JIAUo.c7w84lgCw.UATUUPM8qJm42y'),
(1581, 'Robert Fina', 'robert.fina80@test.com', 'admin', '$2y$10$j5lCcHea.LtTzKrmH2PFAeh41pgklavZng6z6HoBZvfSYY946uH3W'),
(1582, 'Daiki  Mori', 'daiki..mori81@test.com', 'admin', '$2y$10$SfoAUMVzLdiFUIu/zsPxL.kCIjPBxzI6YHi41lxT0X13KhRm5ep7W'),
(1583, 'Sara Pichilengue', 'sara.pichilengue82@test.com', 'invitado', '$2y$10$40ip/4k073TrnV62waKkm./h2qO/wODtC9PcFVpVU7DwCxA6Dm88m'),
(1584, 'Abba Gandula', 'abba.gandula83@test.com', 'estudiante', '$2y$10$cus.TTg3n4xqxVhyzV0zkuxoFAADwHsP5gPlrNizonUy4SxtwHcsi'),
(1585, 'Isabel Segura', 'isabel.segura84@test.com', 'admin', '$2y$10$lUcS/n90kS5LHQDBfUMEzeCHEfntE.dO8W6tY720pFpczmHxhaZHK'),
(1586, 'Xavier Morin', 'xavier.morin85@test.com', 'invitado', '$2y$10$oC4LR1UD0aJZTuqrA.rXSur0Ut/tXo1Fz8d511EOaPm.NeB7Yb1tq'),
(1587, 'Laia de la Penitencia', 'laia.de.la.penitencia86@test.com', 'estudiante', '$2y$10$0SLqWtFWndji/jOsoeaceOImMFEcfPy09Q8SEnKEom2YQJ0I6MFEq'),
(1588, 'Yorinda Elba', 'yorinda.elba87@test.com', 'invitado', '$2y$10$lFmVdfnUP9DpVdCKDIx8y.snhPbm5hW1FlanfhnqVYkGgOO/dOQfu'),
(1589, 'Iria Gil', 'iria.gil88@test.com', 'estudiante', '$2y$10$7oq441T1xqhQeoS.DxjXauZ2Oaw1mJkL0pDxIHMVMgIpa/942X1hq'),
(1590, 'Blanca Verdugo', 'blanca.verdugo89@test.com', 'admin', '$2y$10$kslNhph9CWBG3DU3koOqLOlAD4OaV4HMyFLOQVICxMXeCRZ/vImY.'),
(1591, 'Kagome Pieplano', 'kagome.pieplano90@test.com', 'admin', '$2y$10$kBlJ9XBc2lu1g5nSpR8L5.K0SxTu06XeyGXN9UicnCIRDKGwAHRQq'),
(1592, 'Durand Yoshida', 'durand.yoshida91@test.com', 'estudiante', '$2y$10$UOLy/vvPb8gv7PoWVEXd7.xCNZfCPjon9xu2WBiOU./Gax/Qyryxa'),
(1593, 'Argi Yamagawa', 'argi.yamagawa92@test.com', 'admin', '$2y$10$gJlhDuu8iomN.tD.lH/dQuBVT22UUTT.9H7UcWlAYl/4cxgnkdq/y'),
(1594, 'Pere García', 'pere.garcía93@test.com', 'admin', '$2y$10$ly0M1Y1TKk6smiq0xauXN.vebBJxR3jbyN9WfP0O9IAhQBvqnrlDm'),
(1595, 'Obdulia de Dios', 'obdulia.de.dios94@test.com', 'estudiante', '$2y$10$.ATarzG88tBLSvZKQxIv.u/CycUuVYJYvJItDEWqMDjZy.meDyIP.'),
(1596, 'Sarah Bojan', 'sarah.bojan95@test.com', 'invitado', '$2y$10$RXCq2bjVQtQPhXacUWuS2eHnTCNfGT6zpfD3jp8czNccJoVgf7j5q'),
(1597, 'Leiona Lemaire', 'leiona.lemaire96@test.com', 'estudiante', '$2y$10$cJN5y9RekdHLmzLcThtK4uSMb74WTci4ST9dn.pCqNwFasBbnOL/a'),
(1598, 'Eros López', 'eros.lópez97@test.com', 'estudiante', '$2y$10$yCCNO1UuinMRT2.PfnEMFeK0tiXGVqf0EC90KXlionD/37rBB7OPa'),
(1599, 'Serge Surero', 'serge.surero98@test.com', 'admin', '$2y$10$9Fmew/rsWzI5qqrnWq2QbeJ8ha66ryvDCEAOxeSA8JCT98NWgW1Z.'),
(1600, 'Javier Richard', 'javier.richard99@test.com', 'admin', '$2y$10$GmAfbAE/RlNi1hxqYMX3feDOAL7g70olsam3E3tIayZKmE5ojPoSu');

-- Índices para tablas volcadas

ALTER TABLE `auditoria`
  ADD PRIMARY KEY (`id`);

ALTER TABLE `dispositivos`
  ADD PRIMARY KEY (`dispositivo_id`),
  ADD UNIQUE KEY `mac_address` (`mac_address`),
  ADD KEY `usuario_id` (`usuario_id`);

ALTER TABLE `eventos_monitorizacion`
  ADD PRIMARY KEY (`evento_id`);

ALTER TABLE `logs_acceso`
  ADD PRIMARY KEY (`id`),
  ADD KEY `usuario_id` (`usuario_id`);

ALTER TABLE `recuperacion_tokens`
  ADD PRIMARY KEY (`id`),
  ADD KEY `usuario_id` (`usuario_id`);

ALTER TABLE `redes`
  ADD PRIMARY KEY (`red_id`);

ALTER TABLE `sesiones_conexion`
  ADD PRIMARY KEY (`sesion_id`),
  ADD KEY `dispositivo_id` (`dispositivo_id`);

ALTER TABLE `usuarios`
  ADD PRIMARY KEY (`usuario_id`),
  ADD UNIQUE KEY `email` (`email`);

ALTER TABLE `vulnerabilidades`
  ADD PRIMARY KEY (`vulnerabilidad_id`),
  ADD KEY `dispositivo_id` (`dispositivo_id`);


-- AUTO_INCREMENT de las tablas volcadas

ALTER TABLE `auditoria`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

ALTER TABLE `dispositivos`
  MODIFY `dispositivo_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=801;
--
ALTER TABLE `eventos_monitorizacion`
  MODIFY `evento_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=12;

ALTER TABLE `logs_acceso`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;
  
ALTER TABLE `recuperacion_tokens`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

ALTER TABLE `redes`
  MODIFY `red_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=5;

ALTER TABLE `sesiones_conexion`
  MODIFY `sesion_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=801;

-- Verificamos la estructura de las tablas
DESC Usuarios;
DESC Dispositivos;
DESC Sesiones_Conexion;
DESC Eventos_Monitorizacion;
DESC Vulnerabilidades;
DESC Redes;

-- Verificamos claves primarias y foraneas
SELECT 
    TABLE_NAME, COLUMN_NAME, CONSTRAINT_NAME, REFERENCED_TABLE_NAME, REFERENCED_COLUMN_NAME
FROM 
    information_schema.KEY_COLUMN_USAGE
WHERE 
    TABLE_SCHEMA = 'proyecto'
    AND REFERENCED_TABLE_NAME IS NOT NULL;

-- Validamos relaciones con consultas JOIN
SELECT u.nombre, d.mac_address, d.ip_address, d.tipo_dispositivo
FROM Usuarios u
JOIN Dispositivos d ON u.usuario_id = d.usuario_id;

SELECT s.sesion_id, u.nombre, d.mac_address, s.timestamp_inicio, s.timestamp_fin, s.red
FROM Sesiones_Conexion s
JOIN Dispositivos d ON s.dispositivo_id = d.dispositivo_id
JOIN Usuarios u ON d.usuario_id = u.usuario_id;

SELECT v.vulnerabilidad_id, u.nombre, d.mac_address, v.tipo_vulnerabilidad, v.severidad, v.fecha_deteccion
FROM Vulnerabilidades v
JOIN Dispositivos d ON v.dispositivo_id = d.dispositivo_id
JOIN Usuarios u ON d.usuario_id = u.usuario_id;

-- Buscamos posibles errores en las relaciones
SHOW ENGINE INNODB STATUS;

-- Buscamos datos huerfanos
SELECT * FROM Dispositivos d
LEFT JOIN Sesiones_Conexion s ON d. dispositivo_id= s.dispositivo_id
WHERE s.sesion_id IS NULL;

SELECT * FROM Vulnerabilidades v
LEFT JOIN Sesiones_Conexion s ON v.dispositivo_id = s.dispositivo_id
WHERE s.sesion_id IS NULL;

-- Creamos roles
CREATE ROLE admin;
CREATE ROLE usuario;
CREATE ROLE invitado;

-- Asignamos permisos
GRANT ALL PRIVILEGES ON wishield.* TO 'admin'@'localhost';
GRANT SELECT ON wishield.usuarios TO 'usuario'@'localhost';

-- Creamos una vista restringida para invitados
CREATE VIEW usuarios_invitados AS
SELECT usuario_id, nombre, email FROM usuarios WHERE rol = 'invitado';
GRANT SELECT ON usuarios_invitados TO 'invitado'@'localhost';
