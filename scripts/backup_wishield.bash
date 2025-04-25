#!/bin/bash
# Script: backup_wishield.sh
# Descripción: Realiza un backup automático de la base de datos WiShield y lo almacena con fecha.

DB_NAME="wishield"
BACKUP_DIR="/backups"
DATE=$(date +"%Y-%m-%d_%H-%M-%S")
BACKUP_FILE="$BACKUP_DIR/wishield_backup_$DATE.sql"
MYSQL_USER="root"
MYSQL_PASSWORD="root"

mkdir -p $BACKUP_DIR
mysqldump -u$MYSQL_USER -p$MYSQL_PASSWORD $DB_NAME > $BACKUP_FILE


if [ $? -eq 0 ]; then
    echo "Backup realizado con éxito: $BACKUP_FILE"
else
    echo "Error en el backup." >&2
    exit 1
fi

find $BACKUP_DIR -type f -name "wishield_backup_*.sql" -mtime +7 -exec rm {} \;

exit 0

# Para que se ejecute en crontab crontab -e
# 0 2 * * * /home/pi/scripts/backup_proyecto.sh
