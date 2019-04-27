#!/bin/bash

# Funciones
ok() { echo -e '\e[32m'$1'\e[m'; } # Color verde

EXPECTED_ARGS=4
E_BADARGS=65
MYSQL=`which mysql`

Q1="CREATE DATABASE IF NOT EXISTS $1;"
Q2="CREATE USER $2;"
Q3="GRANT ALL ON $1.* TO '$2'@'localhost' IDENTIFIED BY '$3';"
Q4="USE $1;"
Q5="CREATE TABLE $4(password1 varchar(30),password2 varchar(30));"
Q6="ALTER DATABASE $1 CHARACTER SET 'utf8';"
SQL="${Q1}${Q2}${Q3}${Q4}${Q5}${Q6}"

if [ $# -ne $EXPECTED_ARGS ]
then
  echo "Usage: $0 dbname dbuser dbpass tablename"
  exit $E_BADARGS
fi

$MYSQL -uroot -e "$SQL"

ok "Base de Datos $1 con la tabla $4 y el usuario $2 con el password $3 fueron creados"
