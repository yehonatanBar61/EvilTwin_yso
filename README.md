# EvilTwin Attack/Defence - Networks protection
![A nice photo](for readme/Evil-Twin-Attack-readmepic.png)
### Created by:
- Yehonatan Baruchson
- Shoham Cohen
 - Ori Ariel
 

### Introduction:
This project was created as part of a network protection course at Ariel University. The goal of the project is to build an attack tool called EvilTwin and a defense tool against the same attack.

### Explanation of the attack:
An evil twin attack occurs when a hacker tries to trick users into connecting to a fake Wi-Fi access point that mimics a real network. When the victim connects to the spoofed evil twin network, the data they share gets sent to a server controlled by the attacker. 

### Phases of the attack:
1. The attacker finds a target connected to an open wireless network
2. The attacker disconnects the target from the wireless network, prevents it from connecting to it, and sets up a fake network with the same network name.
3. A victim unknowingly logs onto the fake access point.
4. The attacker can now monitor their behavior and steal whatever data the victim accesses on the fake network.

### Phases of the defence:
1. Sniffing packets in the environment and finding two or more APs that are under the same name
2. Find out if they are sending deauthentication packets as me
3. Disconnecting from them

### Running the project:
1. Clone our project
2. Install all requirements by running: ```sudo sh to_install.sh```
3. Run the program with: ```sudo python3 run.py```

### Running the attack:
1. choose option 1
2. enter 2 interfaces names as requested
3. choose network
4. choose target client
5. attack him (you can press control + c to stop the sending of the packets)
6. create fake AP with the name of the AP that you choose
7. in order to see all passwords press "done" and the passwords will apeer in passwords.txt at the end of the file

### Links that we used: 

https://www.youtube.com/watch?v=bmGlHjKWTUc&t=136s

https://www.youtube.com/watch?v=AxO_xvLCwa0

https://blog.yezz.me/blog/How-To-Start-a-Fake-Access-Point

https://www.allaboutlinux.eu/how-to-run-php-on-ubuntu/

### Comment:
- We used airmon-ng just to kill any processes or services that might interfere with monitoring mode
- Overall we used acapy tools for this task
