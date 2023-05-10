#!/bin/sh

echo Perform all requirements
sudo apt-get update
sudo apt install apache2
sudo apt install hostapd
sudo apt install dnsmaskq
sudo pip3 install scapy
sudo pip3 install faker scapy
sudo apt-get install figlet
sudo pip3 install colorama
sudo apt-get install aircrack-ng
sudo apt install net-tools
sudo apt-get install iptables
sudo cp -rf fake_login/* /var/www/html/
sudo chmod -x /var/www/html/passwords.txt
sudo chmod -x /var/www/html/pass.php
echo Please see that are no errors while installing