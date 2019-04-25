#!/usr/bin/env python
# -*- encoding: utf-8 -*-

import argparse
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
        raw_input('Interface no se encuentra... Por favor introduce otro: ')
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

def use_mode(args):
    if args.mode == "interactivo" or args.mode == "file":
        interface = None
        bssid     = None
        essid     = None
        channel   = None
        txpower   = None
        network   = None
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
            '''
            Codigo para implementar Rouge AP...

            ejemplo de codigo:
            # Configurando la interfaz por el canal que deseamos
            print 'Changing ' + interface + ' to channel ' + channel
            os.system("iwconfig %s channel %d" % (args.interface, 10))#channel))
            '''
        if args.mode == "file":
            pass
    elif args.mode == "args":
        interface = args.interface
        bssid     = args.bssid
        essid     = args.essid
        channel   = args.channel
        txpower   = args.txpower
        network   = args.network
        mask      = args.mask
        gateway   = args.gateway
    else:
        print "\nElige un modo de uso corecto:\n\t[interactivo, args , file]"
    return interface,bssid,essid,channel,txpower,network,mask,gateway

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Implementacion de Evil Twin Attack')
    parser.add_argument('-mode' , '--use-mode'  , dest='mode'      , type=str, required=True,  choices=['interactivo','args','file'] ,help='Modo de uso del programa: Interactivo, Argumentos, Archivo')
    parser.add_argument('-i'    , '--interface' , dest='interface' , type=str, required=False, help='Interface to use for sniffing and packet injection')
    parser.add_argument('-bssid', '--bssid'     , dest='bssid'     , type=str, required=False, help='Direccion MAC del AP')
    parser.add_argument('-essid', '--essid'     , dest='essid'     , type=str, required=False, help='Nombre de la red inalambrica')
    parser.add_argument('-c'    , '--channel'   , dest='channel'   , type=int, required=False, choices=range(1,16) ,help='Canal del AP ')
    parser.add_argument('-p'    , '--txpower'   , dest='txpower'   , type=int, required=False, choices=range(20,31,10), help='Potencia de la antena')
    parser.add_argument('-n'    , '--network'   , dest='network'   , type=str, required=False, help='Network')
    parser.add_argument('-m'    , '--mask'      , dest='mask'      , type=str, required=False, help='Mascara')
    parser.add_argument('-g'    , '--gateway'   , dest='gateway'   , type=str, required=False, help='Gateway')

    args = parser.parse_args()
    use_mode(args)
