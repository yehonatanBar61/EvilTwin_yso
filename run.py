import os
import sys
from colorama import Fore
import time
from datetime import datetime
import attack
import fakeAP
import defence


def print_header(message: str):
    print(Fore.WHITE)
    os.system('figlet -f slant {}'.format(message))

def print_sub_header(message: str):
    print(Fore.GREEN)
    os.system('figlet -f digital {}'.format(message))
    print(Fore.RESET)


def switch_to_monitor_mode(interface):
    os.system("sudo ip link set {0} down".format(interface))
    os.system("sudo iw {0} set monitor control".format(interface))
    os.system("sudo ip link set {0} up".format(interface))
    print(Fore.GREEN + "[+] Switched to monitor mode")

def switch_to_managed_mode(interface):
    os.system("sudo ip link set {0} down".format(interface))
    os.system("sudo iw {0} set type managed".format(interface))
    os.system("sudo ip link set {0} up".format(interface))
    print(Fore.GREEN + "[+] Switched to managed mode")



def restart(fake_ap, wlan_interface):
    """
    reset all
    """
    print(Fore.YELLOW + "[*] cleaning all for a few seconds...")
    os.system('service NetworkManager start')
    os.system('service apache2 stop >/dev/null 2>&1')
    os.system('service hostapd stop >/dev/null 2>&1')
    os.system('service dnsmasq stop >/dev/null 2>&1')
    os.system("killall dnsmasq >/dev/null 2>&1")
    os.system("killall hostapd >/dev/null 2>&1")
    os.system('iptables -F')
    os.system('iptables -t nat -F')
    os.system("sudo rm -f build/hostapd.conf")
    os.system("sudo rm -f build/dnsmasq.conf")
    os.system("rm -rf build/")
    os.system("sudo systemctl unmask systemd-resolved >/dev/null 2>&1")
    os.system("sudo systemctl enable systemd-resolved >/dev/null 2>&1")
    os.system("sudo systemctl start systemd-resolved >/dev/null 2>&1")
    os.system("sudo rm /etc/resolv.conf")
    os.system("sudo ln -s /run/systemd/resolve/resolv.conf /etc/resolv.conf")
    if wlan_interface != 'none' and fake_ap != 'none':
        switch_to_managed_mode(fake_ap)
        switch_to_managed_mode(wlan_interface)
    print(Fore.GREEN + "[$] finished good bye :)")


def run_attack():
    """
        Let's start the attack
    """
    attacker = attack.Attack()
    target_ap = attacker.network_search()
    print(Fore.BLUE + "[*] The target AP is: {}".format(target_ap))
    target_client = attacker.client_search(target_ap)
    print(Fore.BLUE + '[*] The target you choose to attack: {}'.format(target_client))
    attacker.deauth(target_client, target_ap[1],attacker.wlan_interface)   
    attacker.create_fakeAP()

def run_defence():
    """
        Let's start the defence
    """
    defender = defence.defence()

def run():
    print_header("EvilTwin runner")
    print(Fore.BLUE + "Welcome To EvilTwin Runner")

    if os.geteuid() != 0:
        sys.exit('{}Error: This script must be run as root.'.format(Fore.RED))

    while True:
        user_input = input(Fore.YELLOW + '\n(1) Perform Evil Twin Attack\n'
                 '(2) Perform Defence on Evil Twin Attack\n'
                 '(3) CleanUp'
                 'Please select one of the options mentioned above, or write quit to quit the manager\n\n')
        if user_input == '1':
            run_attack()
            break
        if user_input == '2':
            run_defence()
            break
        if user_input == '3':
            restart("none", "none")
            sys.exit()
        else:
            print(Fore.RED + 'Not a valid option, try again please.')
    

if __name__ == '__main__':
    run()



