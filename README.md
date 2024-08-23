<h1>Network Security</h1>
<h2>Part 1: Review Questions</h2>
Before moving on to the lab exercises, complete the following review questions:

<h3>Security Control Types</h3>
The concept of defense-in-depth can be broken down into three security control types. Identify the security control type of each set of defense tactics.
<ul>
<li>Walls, bollards, fences, guard dogs, cameras, and lighting are what type of security control?</li>
<li>Security awareness programs, BYOD policies, and ethical hiring practices are what type of security control?</li>
<li>Encryption, biometric fingerprint readers, firewalls, endpoint security, and intrusion detection systems are what type of security control?</li>
</ul>
<h3>Intrusion Detection and Attack Indicators</h3>
<ul>
    <li>What's the difference between an IDS and an IPS?</li>
    <li>What's the difference between an indicator of attack (IOA) and an indicator of compromise (IOC)?</li>
</ul>

<h3>The Cyber Kill Chain</h3>
Name the seven stages of the cyber kill chain, and provide a brief example of each.
<ul>
    <li>Stage 1:</li>
    <li>Stage 2:</li>
    <li>Stage 3:</li>
    <li>Stage 4:</li>
    <li>Stage 5:</li>
    <li>Stage 6:</li>
    <li>Stage 7:</li>
</ul>

<h3>Snort Rule Analysis</h3>
Use the provided Snort rules to answer the following questions:
<b>Snort Rule #1</b>
                  alert tcp $EXTERNAL_NET any -> $HOME_NET 5800:5820 (msg:"ET SCAN Potential VNC Scan 5800-5820"; flags:S,12; threshold: type both, track by_src, count 5, seconds 60; reference:url,doc.emergingthreats.net/2002910; classtype:attempted-recon; sid:2002910; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
<ul>
   <li>Break down the Snort rule header and explain what this rule does.</li>
   <li>What stage of the cyber kill chain does the alerted activity violate?</li>
   <li>What kind of attack is indicated?</li>
</ul>

<b>Snort Rule #2</b>

alert tcp $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:"ET POLICY PE EXE or DLL Windows file download HTTP"; flow:established,to_client; flowbits:isnotset,ET.http.binary; flowbits:isnotset,ET.INFO.WindowsUpdate; file_data; content:"MZ"; within:2; byte_jump:4,58,relative,little; content:"PE|00 00|"; distance:-64; within:4; flowbits:set,ET.http.binary; metadata: former_category POLICY; reference:url,doc.emergingthreats.net/bin/view/Main/2018959; classtype:policy-violation; sid:2018959; rev:4; metadata:created_at 2014_08_19, updated_at 2017_02_01;)
<ul>
    <li>Break down the Snort rule header and explain what this rule does.</li>
    <li>What layer of the cyber kill chain does the alerted activity violate?</li>
    <li>What kind of attack is indicated?</li>
</ul>

<b>Snort Rule #3</b>
Your turn! Write a Snort rule that alerts when traffic is detected inbound on port <b>4444</b> to the local network on any port. Be sure to include the <b>msg</b> in the rule option.
<h2>Part 2: "Drop Zone" Lab</h2>
In this lab exercise, you will assume the role of a junior security administrator at an indoor skydiving company called Drop Zone.
<ul>
    <li>Your company hosts a web server that accepts online reservations and credit card payments. As a result, your company must comply with PCI/DSS regulations that require businesses who accept online credit card payments to have a firewall in place to protect personally identifiable information (PII).</li>
    <li>Your network has been under attack from the following three IPs: <b>10.208.56.23</b>, <b>135.95.103.76</b>, and <b>76.34.169.118</b>. You have decided to add these IPs to the <b>drop</b> zone within your firewall.</li>
    <li>The first requirement of PCI/DSS regulations is to protect your system with firewalls. "Properly configured firewalls protect your card data environment. Firewalls restrict incoming and outgoing network traffic through rules and criteria configured by your organization." —  <a href="https://www.pcisecuritystandards.org/document_library/#results" target="_blank"> PCI DSS Quick Reference Guide </a> </li>
</ul>

<h3>Set Up</h3>h3>
For this lab, use the web lab virtual machine (VM).
<ul>
    <li>Once logged in, launch the <b>firewalld</b> and ufw docker containers, and create an interactive session with the firewalld container with the following command:</li>
</ul>
<b>docker exec -it firewalld bash</b>

<h3Instructions</h3>
The senior security manager has drafted configuration requirements for your organization with the following specification:
You need to configure zones that will segment each network according to service type.

<ul>
    <li>public Zone</li>
    <ul>
        <li>Services: HTTP, HTTPS, POP3, SMTP</li>
        <li>Interface: ETH0</li>
    </ul>
    <li>web Zone</li>
    <ul>
        <li>Source IP: 201.45.34.126</li>
        <li>Services: HTTP</li>
        <li>Interface: ETH1</li>
    </ul>
    <li>sales Zone</li>
     <ul>
        <li>Source IP: 201.45.15.48</li>
        <li>Services: HTTPS</li>
        <li>Interface: ETH2</li>
     </ul>
    <li>mail Zone</li>
    <ul>
        <li>Source IP: 201.45.105.12</li>
        <li>Services: SMTP, POP3</li>
        <li>Interface: ETH3</li>
    </ul>
</ul>
You also need to drop all traffic from the following blacklisted IPs:
<ul>
   <li>10.208.56.23</li>
    <li>135.95.103.76</li>
    <li>76.34.169.118</li>
</ul>
Reference: <a href="https://manpages.debian.org/testing/firewalld/firewall-cmd.1.en.html" target="_blank"> https://manpages.debian.org/testing/firewalld/firewall-cmd.1.en.html</a>

<h3>Uninstall ufw</h3>
Before getting started, you should verify that you do not have any instances of UFW running. This will avoid conflicts with your firewalld service. This also ensures that firewalld will be your default firewall.
<ul>
    <li>Run the command that removes any running instance of UFW.</li>
</ul>

<h3>Enable and start firewalld.</h3>
By default, the <b>firewalld</b> service should be running. If not, then run the commands that enable and start firewalld upon boots and reboots.
<b>Note:</b> This will ensure that firewalld remains active after each reboot.

<h3>Confirm that the service is running.</h3>
Run the command that checks whether the firewalld service is up and running.

<h3>List all firewall rules currently configured.</h3>
Next, lists all currently configured firewall rules. This will give you a good idea of what's currently configured and save you time in the long run by ensuring that you don’t duplicate work that’s already done.
<ul>
    <li>Run the command that lists all currently configured firewall rules.</li>
    <li>Take note of what zones and settings are configured. You many need to remove unneeded services and settings.</li>
</ul>

<h3>List all supported service types that can be enabled.</h3>
<ul>
    <li>Run the command that lists all currently supported services to find out whether the service you need is available.</li>
    <li>Notice that the <b>home</b> and <b>drop</b> zones are created by default.</li>
</ul>

<h3>Zone views</h3>
<ul>
    <li>Run the command that lists all currently configured zones./li>
    <li>Notice that the  <b>public</b> and  <b>drop</b> zones are created by default. Therefore, you will need to create zones for  <b>web</b>,  <b>sales</b>, and  <b>mail</b>./li>
</ul>

<h3>Create zones for <b>web</b>, <b>sales</b> and <b>mail</b>.</h3>
<ul>
    <li>Run the commands that create <b>web</b>, <b>sales</b>, and <b>mail</b> zones.</li>
</ul>
Remember to reload the firewalld service in order to apply your new settings before moving on. 

<h3>Set the zones to their designated interfaces.</h3>
<ul>
    <li>Run the commands that set your <b>eth</b> interfaces to your zones.</li>
    <ul>
        <li>Use the configurations provided at the beginning of the instructions.</li>
    </ul>
</ul>

<h3>Add services to the active zones.<h3>
<ul>
    <li>Run the commands that add services to the <b>public</b> zone, the <b>web</b> zone, the <b>sales</b> zone, and the <b>mail</b> zone.</li>
    <ul>    
    <li>Use the configurations provided at the beginning of the instructions.</li>
    </ul>
</ul>

<h3>Add your adversaries to the drop zone.<h3>
    Run the command that will add all current and any future blacklisted IPs to the <b>pdrop</b> zone.

<h3> Make rules permanent, then reload them.</h3>
It's good practice to ensure that your firewalld installation remains nailed up and retains its services across reboots. This helps ensure that the network remains secure after unplanned outages such as power failures.
    <ul>
    <li>Run the command that reloads the firewalld configurations and writes it to memory.</li>
    </ul>

<h3>View active zones.</h3>
Now, provide truncated listings of all currently active zones. This is a good time to verify your zone settings.
<ul>
    <li>Run the command that displays all zone services.</li>
</ul>

<h3>Block an IP address.</h3>
    Use a rich-rule that blocks the IP address 138.138.0.3 on your public zone.

<h3>Block Ping/ICMP Requests</h3>
Harden your network against ping scans by blocking icmp ehco replies.
<ul>
    <li> Run the command that blocks pings and icmp requests in your public zone.</li>
</ul>

<h3>Rule Check</h3>
Now that you've set up your brand new firewalld installation, it's time to verify that all of the settings have taken effect.
<ul>
    <li>Run the command that lists all of the rule settings. Run one command at a time for each zone.</li>
    <li>Are all of the rules in place? If not, then go back and make the necessary modifications before checking again.</li>
</ul>
Congratulations! You have successfully configured and deployed a fully comprehensive firewalld installation.

<h2>Part 3: IDS, IPS, DiD, and Firewalls</h2>
Answer the following review questions.

<h3>IDS vs. IPS Systems</h3>
<ul>
   <li>Name and define two ways an IDS connects to a network.</li>
   <li>Describe how an IPS connects to a network.</li>
   <li> What type of IDS compares patterns of traffic to predefined signatures and is unable to detect zero-day attacks?</li>
    <li>What type of IDS is beneficial for detecting all suspicious traffic that deviates from the well-known baseline and is excellent at detecting when an attacker probes or sweeps a network?</li>
</ul>

<h3>Defense-in-Depth</h3>
<ul>
    For each of the following scenarios, provide the layer of defense-in-depth that applies:
<ul>
       <li> A criminal hacker tailgates an employee through an exterior door into a secured facility, explaining that they forgot their badge at home.</li>
       <li> A zero-day goes undetected by antivirus software.</li>
       <li> A criminal successfully gains access to HR’s database.</li>
       <li> A criminal hacker exploits a vulnerability within an operating system.</li>
       <li>A hacktivist organization successfully performs a DDoS attack, taking down a government website.</li>
       <li> Data is classified at the wrong classification level.</li>
       <li>A state-sponsored hacker group successfully firewalked an organization to produce a list of active services on an email server.</li>
</ul>
   <li> Name one method of protecting data-at-rest from being readable on hard drive.</li>
    <li>Name one method of protecting data-in-transit.</li>
    <li>What technology could provide law enforcement with the ability to track and recover a stolen laptop?</li>
    <li>How could you prevent an attacker from booting a stolen laptop using an external hard drive?</li>
</ul>

<h3>Firewall Architectures and Methodologies</h3>
<ul>
    <li>Which type of firewall verifies the three-way TCP handshake? TCP handshake checks are designed to ensure that session packets are from legitimate sources.</li>
    <li>Which type of firewall considers the connection as a whole? Meaning, instead of considering only individual packets, these firewalls consider whole streams of packets at one time.</li>
    <li>Which type of firewall intercepts all traffic prior to forwarding it to its final destination? In a sense, these firewalls act on behalf of the recipient by ensuring the traffic is safe prior to forwarding it.</li>
    <li>Which type of firewall examines data within a packet as it progresses through a network interface by examining source and destination IP address, port number, and packet type—all without opening the packet to inspect its contents?</li>
   <li> Which type of firewall filters solely based on source and destination MAC address?</li>
</ul>
