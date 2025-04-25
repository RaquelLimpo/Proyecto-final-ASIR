#hemos de tener nmap en la raspberry pi
#!/bin/bash

# Configuración
SUBNET="192.168.1.0/24"
MYSQL_USER="root"
MYSQL_PASS="root"
DB="wishield"
CLAVE="TuClaveAES123"

# Escaneo con Nmap
echo "🔍 Escaneando red..."
RESULTS=$(nmap -sn $SUBNET | awk '/Nmap scan report/{ip=$NF}/MAC Address:/{print ip,$3}' | sed 's/[()]//g')

# Insertar resultados
for line in $RESULTS; do
  IP=$(echo $line | awk '{print $1}')
  MAC=$(echo $line | awk '{print $2}')
  echo "💾 Registrando IP: $IP | MAC: $MAC"

  mysql -u$MYSQL_USER -p$MYSQL_PASS $DB -e "
    INSERT INTO Dispositivos (usuario_id, mac_address, ip_address, tipo_dispositivo)
    VALUES (1, AES_ENCRYPT('$MAC', '$CLAVE'), AES_ENCRYPT('$IP', '$CLAVE'), 'Detectado por Pi');
  "
done

echo "✅ Escaneo completado e insertado."

#para crontab:  crontab -e
# 0 * * * * /home/pi/scripts/scan_and_send.sh >> /var/log/wishield_scan.log 2>&1

