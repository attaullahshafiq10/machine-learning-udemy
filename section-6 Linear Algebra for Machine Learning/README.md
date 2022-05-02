Metasploit Tutorial for Beginners – Basics to Advanced
Default imageMAHMUD HASANFEBRUARY 7, 2022PENTESTING, NETWORKING
Metasploit Tutorial for Beginners
Metasploit, one of the most widely used penetration testing tools, is a very powerful all-in-one tool for performing different steps of a penetration test.

If you ever tried to exploit some vulnerable systems, chances are you have used Metasploit, or at least, are familiar with the name. It allows you to find information about system vulnerabilities, use existing exploits to penetrate the system, helps create your own exploits, and much more.

In this tutorial, we’ll be covering the basics of Metasploit Framework in detail and show you real examples of how to use this powerful tool to the fullest.

Table of Contents
Installing Metasploit
Installing Metasploit on Linux
Find out the version of Metasploit and updating
Basics of Penetration testing
1. Information gathering / Reconnaissance
2. Vulnerability Analysis
3. Exploitation
4. Post Exploitation
5. Report
Basics of Metasploit Framework
Modules of Metasploit Framework
1. Exploits
2. Payloads
3. Auxiliaries
4. Encoders
Components of Metasploit Framework
1. msfconsole
2. msfdb
3. msfvenom
4. meterpreter
Metasploit location on the drive
Basic commands of Metasploit Framework
Show command
Search anything within Metasploit
The use command
Get the description of the module with the info command
See the options you need to specify for the modules
Use the set command to set a value to a variable
Choose the Payload
Check if the exploit will work or not
A penetration test walkthrough
Target identification and Host discovery
Port scanning & Service detection
Vulnerability Analysis
Exploiting Vulnerabilities
Exploiting the VSFTPD vulnerability
Keeping the sessions in the background
Exploiting samba smb
Exploiting VNC
Post Exploitation tasks with Metasploit & Meterpreter
What is Meterpreter?
Upgrade to a meterpreter from shell
Meterpreter functionalities
Staying persistently on the exploited machine
Create custom payloads with msfvenom
Check all options for creating your payload
Encoding your payload to evade detection
Checking if your payload can evade anti-virus programs
Conclusion
Installing Metasploit
Metasploit is available for Windows and Linux OS, and you can download the source files from the official repository of the tool in Github. If you are running any OS designed for penetration testing, e.g., Kali Linux, it will be pre-installed in your system. We’ll be covering how to use Metasploit Framework version 6 on Kali Linux. However, the basics will remain the same wherever you’re using Metasploit.

Installing Metasploit on Linux
To install Metasploit in Linux you have to get the package metasploit-framework. On Debian and Ubuntu based Linux distros, you can use the apt utility:

apt install metasploit-framework
On CentOS/Redhat you can the yum utility to do the same:

yum install metasploit-framework
Find out the version of Metasploit and updating
If you’re not sure if you have Metasploit or not, you can confirm by typing msfconsole in your terminal:

msfconsole
 _                                                    _
/ \    /\         __                         _   __  /_/ __                                                                                                                                                      
| |\  / | _____   \ \           ___   _____ | | /  \ _   \ \                                                                                                                                                     
| | \/| | | ___\ |- -|   /\    / __\ | -__/ | || | || | |- -|                                                                                                                                                    
|_|   | | | _|__  | |_  / -\ __\ \   | |    | | \__/| |  | |_                                                                                                                                                    
      |/  |____/  \___\/ /\ \\___/   \/     \__|    |_\  \___\                                                                                                                                                   
                                                                                                                                                                                                                 

       =[ metasploit v6.1.27-dev                          ]
+ – – =[ 2196 exploits - 1162 auxiliary - 400 post       ]
+ – – =[ 596 payloads - 45 encoders - 10 nops            ]
+ – – =[ 9 evasion                                       ]

Metasploit tip: Tired of setting RHOSTS for modules? Try 
globally setting it with setg RHOSTS x.x.x.x
Metasploit Tip: Start commands with a space to avoid saving them to history

As you can see my machine already has Metasploit Framework installed.

Metasploit changes its greeting messages every time you fire up the Metasploit Framework with the msfconsole command, so you might see a different greeting message when you run it.

You can also find out which version is installed once the program loads. Type in version and hit enter to get the answer:

version
Framework: 6.1.27-dev
Console  : 6.1.27-dev
I am using version 6. If you haven’t updated your Metasploit anytime soon, it’s a good idea to update it before starting to use it. This is because if the tool is old then the updated exploits will not get added to the database of your Metasploit Framework. You can update the program by the msfupdate command:

msf6 > msfupdate

[*] exec: msfupdate

msfupdate is no longer supported when Metasploit is part of the operating

system. Please use ‘apt update; apt install metasploit-framework’

As you can see the msfupdate command is not supported. This happened because Metasploit is already a part of the operating system in the Kali Linux updated versions. If you’re using older versions of the Kali Linux, this command will work fine for your system.

Now that you know how to install and update the Metasploit framework, let’s begin learning some of the basics related to Metasploit.

Basics of Penetration testing
Before we begin, let’s familiarize ourselves with some of the steps of a penetration test briefly. If you’re already familiar with the concept then you can just skip ahead to the good part. Let’s list some of the fundamental steps in penetration testing:

Information Gathering / Reconnaissance
Vulnerability Analysis
Exploitation
Post Exploitation
Report
1. Information gathering / Reconnaissance
At the very beginning of any penetration testing, information gathering is done. The more information you can gather about the target, the better it will be for you to know the target system and use the information later in the process. Information may include crucial information like the open ports, running services, or general information such as the domain name registration information. Various techniques and tools are used for gathering information about the target such as – nmap, zenmap, whois, nslookup, dig, maltego, etc.

One of the most used tools for information gathering and scanning is the nmap or Network Mapper utility. For a comprehensive tutorial for information gathering and nmap which you can check out from here.

2. Vulnerability Analysis
In this step, the potential vulnerabilities of the target are analyzed for further actions. Not all the vulnerabilities are of the same level. Some vulnerabilities may give you entire access to the system once exploited while some may only give you some normal information about the system. The vulnerabilities that might lead to some major results are the ones to go forward with from here. This is the step where Metasploit gives you a useful database to work with.

3. Exploitation
After the identified vulnerabilities have been analyzed, this is the step to take advantage of the vulnerabilities.

In this step, specific programs/exploits are used to attack the machine with the vulnerabilities.

You might wonder, where do these exploits come from?

Exploits come from many sources. One of the primary source is the vulnerability and exploit researchers. People do it because there is a lot at stake here i.e., there may be huge sums of money involved as a bounty.

Now, you may ask if the vulnerabilities are discovered, aren’t those application already fixed? The answer is yes, they are. But the fix comes around in the next update of the application.

Those who are already using the outdated version might not get the update and remains vulnerable to the exploits. The Metasploit Framework is the most suitable tool for this step. It gives you the option to choose from thousands of exploits and use them directly from the Metasploit console. New exploits are updated and incorporated in Metasploit regularly. You may also add some other exploits from online exploit databases like Exploit-DB.

Further, not all the exploits are ready-made for you to use. Sometimes you might have to craft your own exploit to evade security systems and intrusion detection systems. Metasploit also has different options for you to explore on this regard.

4. Post Exploitation
This is the step after you’ve already completed exploiting the target system. You’ve got access to the system and this is where you will decide what to do with the system. You may have got access to a low privilege user. You will try to escalate your privilege in this step. You may also keep a backdoor the victim machine to allow yourself to enter the system later whenever you want. Metasploit has numerous functionalities to help you in this step as well.

5. Report
This is the step that many penetration testers will have to complete. After carrying out their testing, the company or the organization will require them to write a detailed report about the testing and improvement to be done.

Now, after the long wait, let’s get into the basics of the actual program – Metasploit Framework.

Basics of Metasploit Framework
In this section, we’ll learn all the basics related to Metasploit Framework. This will help us understand the terminologies related to the program and use the basic commands to navigate through.

Modules of Metasploit Framework
As discussed earlier, Metasploit can be used in most of the penetration testing steps. The core functionalities that Metasploit provides can be summarized by some of the modules:

Exploits
Payloads
