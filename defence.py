import signal
from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Deauth, Dot11Beacon, RadioTap, Dot11Elt
from colorama import Fore

def switch_to_monitor_mode(interface):
    os.system("sudo ip link set {0} down".format(interface))
    os.system("sudo iw {0} set monitor control".format(interface))
    os.system("sudo ip link set {0} up".format(interface))
    print(Fore.GREEN + "[+] Switched to monitor mode")


class defence:

    wlan_interface = 'none'
    ap_list = []
    suspects = []
    attacked = False
    count = 0
    attacked_mac = 'none'


    def __init__(self) -> None:

        os.system("service NetworkManager stop")
        os.system("airmon-ng check kill")

        #os.system("clear")

        print("initing defence")

        print(Fore.RESET + "")

        iwconfig_output = os.popen('iwconfig').read()
        print(iwconfig_output)

        result = False
        while result == False:
            sniffer_w = input(Fore.YELLOW + "[*] Enter the name of the interface you want to work with: ")
            if sniffer_w in iwconfig_output:
                self.wlan_interface = sniffer_w
                result = True
            else:
                print("[*] You entered an invalid name. Please try again.")

        print(Fore.YELLOW + "[*] switching {} to monitor mode".format(self.wlan_interface))
        switch_to_monitor_mode(self.wlan_interface)
        self.network_search()

    

    def handle_network_packet(self, pkt) -> None:
        
        if pkt.haslayer(Dot11Beacon):
            ssid = pkt[Dot11Elt].info.decode()
            mac = pkt[Dot11].addr2

            if mac not in [x[1] for x in self.ap_list[0:]]:
                self.ap_list.append([ssid, mac])
                print(Fore.GREEN + '(+) Found new Access Point : SSID = {} , MAC = {}'.format(ssid, mac))
            
            
                
    def network_search(self, duration: int = 2):
        print(Fore.YELLOW + "[*] starting to sniff for networks")

        channel = 0
        for channel in range(1, 14):
            os.system("iwconfig " + self.wlan_interface + " channel " + str(channel))

            print(Fore.YELLOW + "[*] Sniffing channel {} for {} seconds...".format(channel, duration))
            sniff(timeout=duration, iface=self.wlan_interface, prn=self.handle_network_packet)
        
        flag = False
        for network1 in self.ap_list:
            flag = False
            for network2 in self.ap_list:
                if network1[0] == network2[0] and network1[1] != network2[1]:
                    self.suspects.append(network2)
                    self.ap_list.remove(network2)
                    flag = True
                    continue
            if flag == True:
                self.suspects.append(network1)

        if len(self.suspects) > 0:
            for network in self.suspects:
                print(Fore.RED + "[!] Suspect network: SSID = {} , MAC = {}".format(network[0], network[1]))

        output = input(Fore.YELLOW + "[*] To disconnect from the suspected networks press yes or enter to quit: ")
        if output == 'yes':
            for networks in self.suspects:
                self.disconnect(network[1])


    def disconnect(self, bad_ap):
        print(Fore.YELLOW + "[*] Disconnecting from {}".format(bad_ap))
        client_addr = "ff:ff:ff:ff"
        deauth_tap = RadioTap() / Dot11(addr1=client_addr, addr2=bad_ap,
                                        addr3=bad_ap) / Dot11Deauth()  
        deauth_tc = RadioTap() / Dot11(addr1=bad_ap, addr2=client_addr,
                                    addr3=client_addr) / Dot11Deauth()  
        for i in range(1, 10):
            sendp(deauth_tap, iface=self.wlan_interface, count=100)
            sendp(deauth_tc, iface=self.wlan_interface, count=100)
            time.sleep(2)

    def deauth(self, interface):
        timeout = time.time() + 60
        while True:
            sniff(iface=interface, prn=self.deauth_handler, timeout=30)
            if time.time() > timeout or self.attacked:
                break


    def deauth_handler(self, packet):
        if packet.haslayer(Dot11) and packet.type == 0 and packet.subtype == 12:
            if packet.addr2 is not None and packet.addr3 is not None:
                if packet.addr2 in [x[1] for x in self.suspects[0:]]:  
                    self.count += 1  
                    if self.count > 40:
                        self.attacked = True
                        print("\nYou are under De-authentication attack!! from MAC = {} ".format(packet.addr2))
                        self.attacked_mac = packet.addr2
                        time.sleep(1)
                        return True   
        