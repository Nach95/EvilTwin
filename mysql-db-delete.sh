#!/bin/bash

# Funciones
ok() { echo -e '\e[32m'$1'\e[m'; } # Color verde

EXPECTED_ARGS=2
E_BADARGS=65
MYSQL=`which mysql`

Q1="DROP DATABASE $1;"
Q2="DROP USER $2;"
SQL="${Q1}${Q2}"

if [ $# -ne $EXPECTED_ARGS ]
then
  echo "Usage: $0 dbname dbuser"
  exit $E_BADARGS
fi

$MYSQL -uroot -e "$SQL"

ok "Base de Datos $1 y el usuario $2 fueron borrados"
