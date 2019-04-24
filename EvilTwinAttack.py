#!/usr/bin/env python
# -*- encoding: utf-8 -*-

import argparse
from multiprocessing import Process
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import sys, os, signal
import threading

channel_list = []
essid_list = []
bssid_list = []
enc_list = []
interface='' # monitor interface
networks = {} #vdictionary to store unique APs

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

# Channel hopper
def channel_hopper():
    while True:
        try:
            channel = random.randrange(1,15)
            os.system("iw dev %s set channel %d" % (interface, channel))
            time.sleep(.5)
        except KeyboardInterrupt:
            break
# Capture interrupt signal and cleanup before exiting
def signal_handler(signal, frame):
    p.terminate()
    p.join()
    os.system('cls' if os.name == 'nt' else 'clear')
    # Imprimir cabecera de resultados
    print "{0:3}\t{1:5}\t{2:20}\t{3:20}\t{4:5}".format('ID', 'Canal', 'ESSID', 'BSSID', 'ENC')
    for i in range(len(essid_list)):
        print "{0:3}\t{1:5}\t{2:20}\t{3:20}\t{4:5}".format(i, channel_list[i], essid_list[i], bssid_list[i], enc_list[i])
    print("[*] Stop sniffing")
    return
    #sys.exit(0)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Implementacion de Evil Twin Attack')
    parser.add_argument('-i'    , '--interface' , dest='interface' , type=str, required=True, help='Interface to use for sniffing and packet injection')
    parser.add_argument('-bssid', '--bssid'     , dest='bssid'     , type=str, required=False, help='Direccion MAC del AP')
    parser.add_argument('-essid', '--essid'     , dest='essid'     , type=str, required=False, help='Nombre de la red inalambrica')
    parser.add_argument('-c'    , '--channel'   , dest='channel'   , type=int, required=False, help='Canal del AP ')
    parser.add_argument('-p'    , '--power'     , dest='power'     , type=str, required=False, help='Potencia de la antena')
    parser.add_argument('-m'    , '--mask'      , dest='mask'      , type=str, required=False, help='Mascara')
    parser.add_argument('-g'    , '--gateway'   , dest='gateway'   , type=str, required=False, help='Gateway')
    parser.add_argument('-n'    , '--network'   , dest='network'   , type=str, required=False, help='Network')

    args = parser.parse_args()
    conf.iface = args.interface
    interface = conf.iface

    # Imprimir cabecera del escaneo
    print "Oprima CTRL+C para detener escaneo"
    print "{0:3}\t{1:10}\t{2:20}\t{3:20}".format('CH','ENC','BSSID','SSID')
    # Iniciamos el channel hopper
    p = Process(target = channel_hopper)
    p.start()

    # Capturamos CTRL-C
    signal.signal(signal.SIGINT, signal_handler)

    # Ininicamos el Sniffer
    sniff(iface=interface,prn=sniffAP,timeout=30)
    # Reiniciamos nuestra signal
    signal.signal(signal.SIGINT, signal.SIG_DFL)

    os.system('cls' if os.name == 'nt' else 'clear')
    print "{0:3}\t{1:5}\t{2:20}\t{3:20}\t{4:5}".format('ID', 'Canal', 'ESSID', 'BSSID', 'ENC')
    for i in range(len(essid_list)):
        print "{0:3}\t{1:5}\t{2:20}\t{3:20}\t{4:5}".format(i, channel_list[i], essid_list[i], bssid_list[i], enc_list[i])

    target_bssid = raw_input('Introduce el BSSID de la red Wifi a clonar ')
    while target_bssid not in networks:
        raw_input('BSSID no se encuentra... Por favor introduce otro: ')

    # Configurando la interfaz por el canal que deseamos
    print 'Changing ' + args.interface + ' to channel ' + str(networks[target_bssid][1])
    os.system("iwconfig %s channel %d" % (args.interface, networks[target_bssid][1]))
