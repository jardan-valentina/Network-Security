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
