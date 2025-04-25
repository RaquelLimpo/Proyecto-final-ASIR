#!/bin/bash
# Nombre: acceso_fallido.sh
#Descripción: detecta intentos fallidos y avisa

LOG_FILE="/var/log/mysql/error.log"
ADMIN_EMAIL="admin@wishield.com"

ATTEMPTS=$(grep "Access denied" $LOG_FILE | tail -n 10)

if [ ! -z "$ATTEMPTS" ]; then
  echo "⚠️ Se han detectado intentos de acceso fallidos en la base de datos:"
  echo "$ATTEMPTS"
  echo -e "Asunto: ⚠️ Alerta de Acceso Fallido en MySQL\n" \
          "Se han detectado intentos de acceso fallidos en la base de datos.\n\n" \
          "$ATTEMPTS" | sendmail -v "$ADMIN_EMAIL"

  echo "⚠️ Se ha enviado una alerta a $ADMIN_EMAIL con los intentos de acceso fallidos."
fi
