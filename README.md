# EvilTwin
# Herramienta para auditoria de redes Wi-Fi

## Objetivo

Crear una pieza de software de tipo standlone que sea usada para la auditoria de redes Wi-Fi mediante un ataque de Evil Twin.

## Descripción del proyecto

Se debe seguir alguna metodología de desarrollo de sistemas para la creación, pruebas y liberación de un programa de tipo standlone que sea 
usado para auditar redes Wi-Fi, mediante la automatización de Evil Twin.

## Generalidades

Realizada para el sistema operativo Kali Linux, esta herramienta debe verificar si se cuentan con los paquetes necesarios para su 
funcionamiento en caso de que no se cuenta con uno, la herramienta instalara el recurso faltante, la automatización del ataque cuenta
con las siguientes características implementadas:
- Selección de Access Point a clonar.
- Configuración de interfaz de red en modo monitor.
- Creación de la red local mediante DHCP.
- Des autenticación de equipos conectados al AP real.
- Creación de un portal cautivo para redirigir el tráfico a un formulario de autenticación.
- Servidor web para mostrar portal cautivo.
- Servidor de bases de datos para almacenar las credenciales obtenidas.

Las opciones con las que cuenta la herramienta (en sus 3 formas de ejecución) son las siguientes:
-	Nombre del Access Point por clonar (ESSID).
-	Dirección MAC del Access Point por clonar (BSSID).
-	Canal en el que se comunicará el AP.
-	Potencia a la que funcionará la tarjeta de red.
-	Características de la red local a crear (Máscara, Gateway, etc).
-	Diseño de portal cautivo a utilizar. 

## Modos de uso
**Forma interactiva**

En este modo de uso el usuario selecciona todos los parametros necesarios para la ejecucion de la herramienta, empezando con la seleccion
de la interfaz de red, una vez seleccionada se le recomendara hacer cambio de la potencia de la antena, enseguida se cambiara a modo 
monitor, mostrando todos los access point cercanos, se le pedira que ingrese el BSSID del access point que desee, una vez ingresado esto
se le mostrara dos opciones para la configuracion del servidor DHCP, el usuario debera seleccionar una, una vez ingresado todo esto se 
creara un access point falso con el nombre del access point seleccionado anteriormente, y se des autenticaran los usuarios que esten en 
el access point verdadero, se creara un sitio web falso donde las victimas ingresaran las credenciales validas a ese access point y se 
almacenaran en una base de datos, un ejemplo de la ejecucion se muestra a continuacion:

```
python evil.py -u interactivo
```

**Mediante Argumentos en la linea de comandos**

En este modo el usuario pasara como argumentos en la linea de comandos por medio del uso de banderas las cuales son el modo de uso, la 
interfaz de red, el BSSID, ESSID, la primera direccion IP donde empezara el pool para asignar direcciones IP mediante DHCP, la ultima 
direccion IP del pool de direcciones de DHCP, el gateway y la potencia de la antena, se hace el mismo proceso como en el modo interactivo 
pero el usuario no ingresa ningun dato mientras se ejecuta el programa, un ejemplo de la ejecucion se muestra a continuacion:

```
python evil.py -u args -i wlan0 -b 18:4A:6F:6C:E2:88 -e INFINITUMFDCA -c 8 -f 192.170.0.100 -l 192.170.0.150 -m 255.255.255.0 -g 192.170.0.1 -p 0
```

**Mediante un archivo de configuracion**

En este modo de operacion es parecido a argumentos en la linea de comandos, pero en este caso las banderas en lugar de ponerlas en la linea
de comandos las ponemos en un archivo de configuracion, un ejemplo de la ejecucion se muestra a continuacion:

```
python evil.py -u file -F archivo.conf -i wlan0
```
