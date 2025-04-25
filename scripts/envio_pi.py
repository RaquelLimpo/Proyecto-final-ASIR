# envio_pi.py
# Envia datos de conexión de dispositivos desde la Raspberry Pi a la base de datos de WiShield

import mysql.connector
from datetime import datetime
import time
import random

# Configuración de conexión
config = {
    'host': 'localhost',          # Cambiar si la BD está en otra máquina
    'user': 'pi_user',            # Usuario con permisos LIMITADOS
    'password': 'clave_pi_segura',
    'database': 'wishield'
}

# Simular dispositivos conectados
dispositivos = [801, 802, 803, 804]

while True:
    try:
        conn = mysql.connector.connect(**config)
        cursor = conn.cursor()

        dispositivo_id = random.choice(dispositivos)
        inicio = datetime.now()
        fin = inicio  # Para la simulación, sesión instantánea

        red_id = random.randint(1, 3)  # Simulamos que hay 3 redes configuradas
        sql = """
        INSERT INTO sesiones_conexion (dispositivo_id, timestamp_inicio, timestamp_fin, red_id)
        VALUES (%s, %s, %s, %s)
        """
        cursor.execute(sql, (dispositivo_id, inicio, fin, red_id))
        conn.commit()
        print(f"✅ Sesión insertada: Dispositivo {dispositivo_id}, Red {red_id}, {inicio}")

        cursor.close()
        conn.close()

    except mysql.connector.Error as e:
        print(f"❌ Error al insertar sesión: {e}")

    time.sleep(10)  # Esperar 10 segundos antes de enviar otro dato
