#!/bin/bash

# Variables
DB_NAME="wishield"
DB_USER="root"
DB_PASSWORD="root"
CSV_FILE="/home/pi/datos/datos_prueba.csv"
TABLE_NAME="usuarios"

# Importar datos
mysql -u$DB_USER -p$DB_PASSWORD -e "
LOAD DATA INFILE '$CSV_FILE'
INTO TABLE $DB_NAME.$TABLE_NAME
FIELDS TERMINATED BY ','
LINES TERMINATED BY '\n'
IGNORE 1 ROWS;"

echo "Carga de datos completada desde $CSV_FILE"
