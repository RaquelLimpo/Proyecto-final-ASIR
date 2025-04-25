#!/bin/bash
# nombre: restaurar_backup.sh
#Descripción: restaura un backup especifico

DB_NAME="wishield"
DB_USER="root"
DB_PASSWORD="root"
BACKUP_FILE="$1"

if [ -z "$BACKUP_FILE" ]; then
  echo "Uso: $0 <archivo_backup.sql.gz>"
  exit 1
fi


if [[ $BACKUP_FILE == *.gz ]]; then
  gunzip -c $BACKUP_FILE | mysql -u$DB_USER -p$DB_PASSWORD $DB_NAME
else
  mysql -u$DB_USER -p$DB_PASSWORD $DB_NAME < $BACKUP_FILE
fi

echo "Restauración completada desde $BACKUP_FILE"

#para usarlo ./restore_backup.sh /home/pi/backups/proyecto-2024-03-19_02-00-00.sql.gz
