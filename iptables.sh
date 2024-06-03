#!/bin/bash
# autor: Oscar FM
# Firewall personalizada para "Tijolo Técnico" 
# Esta máquina tem o IP dinâmico para a WAN e IP estático para a LAN 
# Esta máquina tem o Debian instalado
# Nota: Instalar ( apt install iptables-persistence ) 

# SSH server Port.
# # Ignore this if you don't use/don't have an SSH server.
# # Default: 22 (ssh)
SSH="22"
#
# # All ports of running webservers.
# # Ignore this if you don't have them.
# # If you wanna add a port, it should look like "80,443,8080".
# # Default: 80
HTTP="80,443"
#
# # Connection limit
# # Default: 50 connections
CL="50"
#
# # Connection limit action
# # Default: DROP
CLA="DROP"
#
# # IP Block action
# # Default: DROP
IBA="DROP"
#
# # SYN PPS limit
# # Default: 5/s
SPL="5/s"
#
# # SYN-ACK PPS limiL
# # Default: 5/s
SAPL="5/s"
#
# # RST PPS limit
# # Default: 2/s
RPL="2/s"
#
# # UDP PPS limit
# # Default: 3000/s
UPL="3000/s"
#
# # ICMP PPS limit
# # Default: 2/s
IPL="2/s"
#
# # Hashtable size (buckets)
# # Default: 65536
HTS="65536"
#
# # Hashtable max entries in the hash
# # Default: 65536
HTM="65536"
#
# # Hashtable expire (ms)
# # Default: 5 minutes (300000 ms)
HTE="300000"
#
# # MSS limit
# # Default: 536:65535
MSS="536:65535"
#
# # Packet state filter
# # Default: INVALID
# # Add "UNTRACKED" for additional protection. But this may cause problems!
ST="INVALID"
#
# # Limited UDP source ports (against amplification
# # Default: 19,53,123,111,123,137,389,1900,3702,5353
LUSP="19,53,123,111,123,137,389,1900,3702,5353"
#
# # Invalid TCP Flag packet action
# # Default: DROP
ITFPA="DROP"
#
# # Outgoing port-unreach limit
# # Default: 5/m
OPL="5/m"
#
# # Outgoing TCP RST limit
# # Default: 10/s
OTRL="10/s"

# IPTABLES Command 
IPTABLES="/usr/sbin/iptables"
IPTSave="/usr/sbin/iptables-save > /etc/iptables/rules.v4"

# DNS da máquina da WAN  
DNS="1.1.1.1"
#DNS1="192.168.1.68"
#DNS2="192.168.1.254"
#DNS3="8.8.8.8"

# Network Cards 
LOOPBACK="127.0.0.1/8"
#WAN="f0"
LAN="enp3s0"

# Negar todo o tráfico 
$IPTABLES -P INPUT ACCEPT
$IPTABLES -P FORWARD ACCEPT
$IPTABLES -P OUTPUT ACCEPT

# Flush: apagar todas as regras anteriores
$IPTABLES -F
$IPTABLES -X 
$IPTABLES -Z 

$IPTABLES -t nat -F 
$IPTABLES -t nat -X 
$IPTABLES -t mangle -F
$IPTABLES -t mangle -X 
$IPTABLES -t raw -F 
$IPTABLES -t raw -X 

# #Aceita conecções da placa local mas rejeita pacotes que declarem terem origem na placa local
$IPTABLES -A INPUT -i lo -p tcp -m tcp --syn -s 127.0.0.1/255.0.0.0 -j ACCEPT
$IPTABLES -A OUTPUT -o lo -p tcp -m tcp --syn -s 127.0.0.1/255.0.0.0 -j ACCEPT
$IPTABLES -A INPUT -s $LOOPBACK ! -i lo -j DROP 

# Aceitar o comando PING desde o Computador pessoal para a Firewall mas limita a 1s por cada ping 
# Isto para evitar possíveis reconhecimentos de Máquina e outros ataques tal como o Denial of Service  
# ICMP Packets -> PING  
$IPTABLES -A INPUT -i $LAN -p icmp -j DROP
$IPTABLES -A INPUT -i $LAN -p icmp --icmp-type echo-request -m limit --limit 1/s -j ACCEPT 
$IPTABLES -A INPUT -i $LAN -p icmp -m state --state NEW --icmp-type 8 -j ACCEPT 
$IPTABLES -A OUTPUT -o $LAN -p icmp -m state --state NEW --icmp-type 8 -j ACCEPT 

# dayTime 
# port 37 
#$IPTABLES -A OUTPUT -o  -p 37 -m state --state ESTABLISHED -j ACCEPT 
#$IPTABLES -A INPUT -i  -p 37 -m state --state NEW -j ACCEPT 

# Aceitar saidas de procura de DNS - DUAL CARD EXAMPLES
# DNS 1 
# $IPTABLES -A OUTPUT -o $LAN -p udp -s $WAN -d $DNS1 --sport 49152:65535 --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT
# $IPTABLES -A INPUT -i $LAN -p udp -s $DNS1 -d $WAN --sport 49152:65535 --dport 53 -m state --state ESTABLISHED -j ACCEPT 
# DNS 2 #$IPTABLES -A OUTPUT -o $LAN -p udp -s $WAN -d $DNS2 --sport 49152:65535 --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT
# $IPTABLES -A INPUT -i $LAN -p udp -s $DNS2 -d $WAN --sport 49152:65535 --dport 53 -m state --state ESTABLISHED -j ACCEPT 
# DNS 3  
#$IPTABLES -A OUTPUT -o $LAN -p udp -s $WAN -d $DNS3 --sport 49152:65535 --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT
#$IPTABLES -A INPUT -i $LAN -p udp -s $DNS3 -d $WAN --sport 49152:65535 --dport 53 -m state --state ESTABLISHED -j ACCEPT
# DNS 4
#$IPTABLES -A OUTPUT -o $LAN -p udp -s $WAN -d $DNS4 --sport 49152:65535 --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT
#$IPTABLES -A INPUT -i $LAN -p udp -s $DNS4 -d $WAN --sport 49152:65535 --dport 53 -m state --state ESTABLISHED -j ACCEPT 
#$IPTABLES -A OUTPUT -o  -p tcp --dport 53 -m state --state NEW -m comment --comment "Allow Public DNS QUERY" -j ACCEPT 

# Using Suricata to intercept traffic 
#$IPTABLES -I INPUT -p tcp --sport 80 -j NFQUEUE
#$IPTABLES -I OUTPUT -p tcp --dport 80 -j NFQUEUE
# DualCard Suricata Config
#$IPTABLES -I FORWARD -i $LAN -o $WAN -j NFQUEUE
#$IPTABLES -I FORWARD -i $WAN -o $LAN -j NFQUEUE

# ACeitar saidas de procura de DNS - Single Card 
#$IPTABLES -A OUTPUT -o $LAN -p udp -m state --state NEW -j ACCEPT 
#$IPTABLES -A INPUT -i $LAN -p udp -m state --state ESTABLISHED -j ACCEPT 
$IPTABLES -A OUTPUT -o $LAN  -p udp -m udp --dport 53 -m state --state NEW -j ACCEPT 
$IPTABLES -A OUTPUT -o $LAN -p tcp --syn --dport 53 -m connlimit --connlimit-above 2 -j REJECT --reject-with tcp-reset
$IPTABLES -A INPUT -i $LAN -p udp -m udp --dport 53 -m state --state ESTABLISHED -j ACCEPT 

# Aceitar ligação externa via http e https com uma única placa de rede - SINGLE CARD
$IPTABLES -A OUTPUT -o $LAN -p tcp -m tcp --dport 80 -m state --state NEW -j ACCEPT
$IPTABLES -A INPUT -i $LAN -p tcp -m tcp --dport 80 -m state --state ESTABLISHED -j ACCEPT
$IPTABLES -A OUTPUT -o $LAN -p tcp -m tcp --dport 443 -m state --state NEW -j ACCEPT
$IPTABLES -A INPUT -i $LAN -p tcp -m tcp --dport 443 -m state --state ESTABLISHED -j ACCEPT

# Accept thunderbird  ( email Client ) with IMAP Calls 
$IPTABLES -A OUTPUT -o $LAN -p tcp -m tcp --dport 993 -m state --state NEW -j ACCEPT
$IPTABLES -A INPUT -i $LAN -p tcp -m tcp --dport 993 -m state --state ESTABLISHED -j ACCEPT

# Local HTTP-server 
$IPTABLES -A OUTPUT -o $LAN -p tcp -m tcp --dport 8080 -m state --state NEW -j ACCEPT
$IPTABLES -A INPUT -i $LAN -p tcp -m tcp --dport 8080 -m state --state ESTABLISHED -j ACCEPT

# TOR network
$IPTABLES -A OUTPUT -o $LAN -p tcp -m tcp --dport 9050 -m state --state NEW -j ACCEPT
$IPTABLES -A INPUT -i $LAN -p tcp -m tcp --dport 9050 -m state --state ESTABLISHED -j ACCEPT

# Privoxy Ports 
$IPTABLES -A OUTPUT -o $LAN -p tcp -m tcp --dport 8118 -m state --state NEW -j ACCEPT
$IPTABLES -A INPUT -i $LAN -p tcp -m tcp --dport 8118 -m state --state ESTABLISHED -j ACCEPT

# LOG HTTP connections
#$IPTABLES -A OUTPUT -o $LAN -p tcp -m tcp --dport 80 -m state --state NEW -j LOG --log-prefix "iptables_OUTPUT_log: " --log-level 7
#$IPTABLES -A INPUT -i $LAN -p tcp -m tcp --dport 80 -m state --state ESTABLISHED -j LOG --log-prefix "iptables_INPUT_log: " --log-level 7

# LOG SSL connections
#$IPTABLES -A OUTPUT -o $LAN -p tcp -m tcp --dport 443 -m state --state NEW -j LOG --log-prefix "iptables_OUTPUT_log: " --log-level 7
#$IPTABLES -A INPUT -i $LAN -p tcp -m tcp --dport 443 -m state --state ESTABLISHED -j LOG --log-prefix "iptables_INPUT_log: " --log-level 7

# Aceitar ligação externas para fazer o update, ou instalar software usando o comando apt com duas placas de rede
#$IPTABLES -A OUTPUT -o $LAN -p tcp -m tcp -s $wan --sport 49152:65535 -d 0/0 --dport 80 -m state --state new,established -j ACCEPT
#$IPTABLES -A INPUT -i $LAN -p tcp -s 0/0 -d $wan --sport 80 --dport 49152:65535 -m state --state established -j ACCEPT 
#$IPTABLES -A OUTPUT -o $LAN -p tcp -m tcp -s $wan --sport 49152:65535 -d 0/0 --dport 443 -m state --state new,established -j ACCEPT
#$IPTABLES -A INPUT -i $LAN -p tcp -s 0/0 -d $wan --sport 443 --dport 49152:65535 -m state --state established -j ACCEPT 

# Aceita ligações de SSH a partir do computador pessoal ( só e mais nenhum ) 
# $IPTABLES -A INPUT -p tcp -s 10.0.0.101 --dport 22 -m conntrack --ctstate NEW,ESTRABLISHED -j LOG 
# $IPTABLES -A INPUT -p tcp -s 10.0.0.101 --dport 22 -m conntrack --ctstate NEW,ESTRABLISHED -j ACCEPT 
#$IPTABLES -A OUTPUT -o  -p tcp --sport 22 -m conntrack --ctstate NEW,ESTABLISHED -j LOG
#$IPTABLES -A OUTPUT -o $LAN -p tcp -m tcp --dport 22 -m state --state NEW -m comment --comment "Allow Private SSH Sessions" -j ACCEPT 
#$IPTABLES -A INPUT -i $LAN -p tcp -m tcp --dport 22 -m state --state ESTABLISHED -m comment --comment "Allow Private SSH Sessions" -j ACCEPT 
#$IPTABLES -A INPUT -i $LAN -p tcp --syn --dport 22 -m connlimit --connlimit-above 3 -j REJECT

# EMAIL Default Ports 
#$IPTABLES -A OUTPUT -o $LAN -p tcp -m tcp --dport 25 -m state --state NEW -m comment --comment "Allow Port 25 for Email Client" -j ACCEPT 
#$IPTABLES -A INPUT -i $LAN -p tcp -m tcp --dport 25 -m state --state ESTABLISHED -m comment --comment "Allow Port 25 for Email Client" -j ACCEPT 
#$IPTABLES -A OUTPUT -o $LAN -p tcp -m tcp --dport 465 -m state --state NEW -m comment --comment "Allow Port 465 for Email Client" -j ACCEPT 
#$IPTABLES -A INPUT -i $LAN -p tcp -m tcp --dport 465 -m state --state ESTABLISHED -m comment --comment "Allow Port 465 for Email Client" -j ACCEPT 
#$IPTABLES -A OUTPUT -o $LAN -p tcp -m tcp --dport 587 -m state --state NEW -m comment --comment "Allow Port 465 for Email Client" -j ACCEPT 
#$IPTABLES -A INPUT -i $LAN -p tcp -m tcp --dport 587 -m state --state ESTABLISHED -m comment --comment "Allow Port 465 for Email Client" -j ACCEPT 

# Aceita ligações para o Webmin a partir do computador pessoa ( só e mais nenhum ) 
#$IPTABLES -A INPUT -p tcp -s 10.0.0.101 --dport 10000 -m conntrack --ctstate NEW,ESTRABLISHED -j ACCEPT 
#$IPTABLES -A OUTPUT -p tcp --sport 10000 -m conntrack --ctstate ESTABLISHED -j ACCEPT 

# Preparar para redireccionar tráfico: 
# echo "1" > /proc/sys/net/ipv4/ip_forward 

# re-direccionamento do tráfico ( desde rede local para rede externa ) 
# $IPTABLES -t nat -A POSTROUTING -o $WAN -j MASQUERADE 
# $IPTABLES -A FORWARD -i $WAN -o $LAN -m state --state RELATED,ESTRABLISHED -j ACCEPT 
# $IPTABLES -A FORWARD -i $LAN -o $WAN -j ACCEPT 

# Block packages that are not SYN 
$IPTABLES -A INPUT -i $LAN -p tcp -m tcp ! --syn -m state --state NEW -j LOG
$IPTABLES -A INPUT -i $LAN -p tcp -m tcp ! --syn -m state --state NEW -j DROP

# Block with Bogus Flags 
$IPTABLES -t mangle -A PREROUTING -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -j DROP
$IPTABLES -t mangle -A PREROUTING -p tcp -m tcp --tcp-flags FIN,SYN FIN,SYN -j DROP
$IPTABLES -t mangle -A PREROUTING -p tcp -m tcp --tcp-flags SYN,RST SYN,RST -j DROP
$IPTABLES -t mangle -A PREROUTING -p tcp -m tcp --tcp-flags FIN,RST FIN,RST -j DROP
$IPTABLES -t mangle -A PREROUTING -p tcp -m tcp --tcp-flags FIN,ACK FIN -j DROP
$IPTABLES -t mangle -A PREROUTING -p tcp -m tcp --tcp-flags ACK,URG URG -j DROP
$IPTABLES -t mangle -A PREROUTING -p tcp -m tcp --tcp-flags ACK,FIN FIN -j DROP
$IPTABLES -t mangle -A PREROUTING -p tcp -m tcp --tcp-flags ACK,PSH PSH -j DROP
$IPTABLES -t mangle -A PREROUTING -p tcp -m tcp --tcp-flags ALL ALL -j DROP
$IPTABLES -t mangle -A PREROUTING -p tcp -m tcp --tcp-flags ALL NONE -j DROP
$IPTABLES -t mangle -A PREROUTING -p tcp -m tcp --tcp-flags ALL FIN,PSH,URG -j DROP
$IPTABLES -t mangle -A PREROUTING -p tcp -m tcp --tcp-flags ALL SYN,FIN,PSH,URG -j DROP
$IPTABLES -t mangle -A PREROUTING -p tcp -m tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP
#$IPTABLES -t mangle -A PREROUTING -p tcp --syn -m recent --name blacklist --set -j DROP
#$IPTABLES -t mangle -A PREROUTING -p tcp --tcp-flags ALL SYN,ACK -m recent --name blacklist --rcheck --seconds 60 --hitcount 10 -j DROP

# To relieve server load during TCP Out-Of-State Floods, restrict the outgoing TCP RST packets per second (PPS).
# ----------------------------------------------------------------
"$IPTABLES" -t raw -A OUTPUT -o $LAN -p tcp --tcp-flags RST RST -m limit --limit "$OTRL" -j ACCEPT
"$IPTABLES" -t raw -A OUTPUT -o $LAN -p tcp --tcp-flags RST RST -j DROP
#
# Safeguard against CPU overload during amplificated DDoS attacks by limiting DNS/NTP packets per second rate (PPS).
# ----------------------------------------------------------------
#"$IPTABLES" -t raw -A PREROUTING -p udp -m multiport --sports "$LUSP" -m hashlimit --hashlimit-mode srcip,srcport --hashlimit-name Amplification-Limit --hashlimit-above 256/m -j DROP
#
# Drop SYN packets with source-port <1024 to prevent some attacks.
# ----------------------------------------------------------------
"$IPTABLES" -t raw -I PREROUTING -p tcp --syn ! --sport 1024:65535 -m comment --comment "SYN: Invalid Source Port" -j DROP
#
# Drop all packets with the invalid state.
# ----------------------------------------------------------------
"$IPTABLES" -t mangle -I PREROUTING -p all -m conntrack --ctstate "$ST" -m comment --comment "Packet State Filter" -j DROP
#
# Restrict the number of connections per IP to mitigate the impact of Handshake and Slowloris attacks.
# ----------------------------------------------------------------
#"$IPTABLES" -t mangle -A PREROUTING -p tcp -m connlimit --connlimit-above "$CL" --connlimit-mask 50 -m comment --comment "Connection Limit" -j "$CLA"

# Drop new non-SYN TCP packets to mitigate common TCP attacks.
# If you're trying to optimize the ruleset, check this rule. It may affect performance.
# ----------------------------------------------------------------
"$IPTABLES" -t mangle -I PREROUTING -p tcp ! --syn -m conntrack --ctstate NEW -m comment --comment "State NEW but not SYN" -j DROP
#
# Drop TCP packets with invalid MSS to mitigate certain attack types.
# Try to set max MSS to 8960/1460 if you want stricter protection.
# But then you'll need to modify the rule and do this only for your NIC.
# ----------------------------------------------------------------
"$IPTABLES" -t mangle -I PREROUTING -p tcp -m conntrack --ctstate NEW -m tcpmss ! --mss "$MSS" -m comment --comment "Invalid MSS" -j DROP

# Port Scans
$IPTABLES -N port-scanning
$IPTABLES -A port-scanning -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 1/s --limit-burst 2 -j RETURN
$IPTABLES -A port-scanning -j DROP
$IPTABLES -A INPUT -i $LAN -p tcp --dport ssh -m conntrack --ctstate NEW -m recent --set
$IPTABLES -A INPUT -i $LAN -p tcp --dport ssh -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 10 -j DROP
$IPTABLES -N syn_flood

$IPTABLES -A INPUT -i $LAN -p tcp --syn -j syn_flood
$IPTABLES -A syn_flood -m limit --limit 1/s --limit-burst 3 -j RETURN
$IPTABLES -A syn_flood -j DROP
$IPTABLES -A INPUT -i $LAN -p icmp -m limit --limit 1/s --limit-burst 1 -j ACCEPT
$IPTABLES -A INPUT -i $LAN -p icmp -m limit --limit 1/s --limit-burst 1 -j LOG --log-prefix PING-DROP:
$IPTABLES -A INPUT -i $LAN -p icmp -j DROP


# Mitigate Some TCP Floods with hashlimit 
#$IPTABLES -t raw -A PREROUTING -p tcp --syn -m hashlimit --hashlimit-mode srcip --hashlimit-srcmask 32 --hashlimit-dstmask 32 --hashlimit-name synflood --hashlimit-above "$SPL" --hashlimit-htable-expire "$HTE" --hashlimit-htable-size "$HTS" --hashlimit-htable-max "$HTM" -j DROP
#$IPTABLES -t raw -A PREROUTING -p tcp --tcp-flags SYN,ACK SYN,ACK -m hashlimit --hashlimit-mode srcip --hashlimit-srcmask 32 --hashlimit-dstmask 32 --hashlimit-name synackflood --hashlimit-above "$SAPL" --hashlimit-burst 2 --hashlimit-htable-expire "$HTE" --hashlimit-htable-size "$HTS" --hashlimit-htable-max "$HTM" -j DROP
#$IPTABLES -t raw -A PREROUTING -p tcp --tcp-flags RST RST -m hashlimit --hashlimit-mode srcip --hashlimit-srcmask 32 --hashlimit-dstmask 32 --hashlimit-name rstflood --hashlimit-above "$RPL" --hashlimit-burst 2 --hashlimit-htable-expire "$HTE" --hashlimit-htable-size "$HTS" --hashlimit-htable-max "$HTM" -j DROP
# Mitigate UDP Floods with hashlimit.
# # ----------------------------------------------------------------
#$IPTABLES -t raw -A PREROUTING -p udp -m hashlimit --hashlimit-above "$UPL" --hashlimit-mode srcip --hashlimit-srcmask 32 --hashlimit-dstmask 32 --hashlimit-name udp-flood-limit --hashlimit-burst "$UPL" --hashlimit-htable-size "$HTS" --hashlimit-htable-max 65536 --hashlimit-htable-expire "$HTE" -j DROP
#$IPTABLES -t raw -A PREROUTING -p icmp -m comment --comment "ICMP hashlimit" -m hashlimit --hashlimit-mode srcip --hashlimit-srcmask 32 --hashlimit-dstmask 32 --hashlimit-name icmp-limit --hashlimit-above "$IPL" --hashlimit-burst 2 --hashlimit-htable-size "$HTS" --hashlimit-htable-max 65536 --hashlimit-htable-expire "$HTE" -j DROP
"$IPTABLES" -t raw -A PREROUTING -p icmp --icmp-type address-mask-request -j DROP
"$IPTABLES" -t raw -A PREROUTING -p icmp --icmp-type router-solicitation -j DROP
"$IPTABLES" -t raw -A PREROUTING -p icmp --icmp-type timestamp-request -j DROP
"$IPTABLES" -t raw -A PREROUTING -p icmp --icmp-type redirect -j DROP


# Prevent SQL Injection
$IPTABLES -t raw -I PREROUTING -p tcp --dport 3306 -m string --string "union select" --algo bm -j DROP
$IPTABLES -t raw -I PREROUTING -p tcp --dport 3306 -m string --string "information_schema" --algo bm -j DROP

# User Agente Filter 
$IPTABLES -t raw -A PREROUTING -p tcp -m multiport --dports 80 -m string --string 'python-requests' --algo kmp -j DROP
$IPTABLES -t raw -A PREROUTING -p tcp -m multiport --dports 80 -m string --string 'benchmark' --algo kmp -j DROP
$IPTABLES -t raw -A PREROUTING -p tcp -m multiport --dports 80 -m string --string 'MD5(' --algo kmp -j DROP
$IPTABLES -t raw -A PREROUTING -p tcp -m multiport --dports 80 -m string --string 'censys' --algo kmp -j DROP
$IPTABLES -t raw -A PREROUTING -p tcp -m multiport --dports 80 -m string --string 'inspect' --algo kmp -j DROP
$IPTABLES -t raw -A PREROUTING -p tcp -m multiport --dports 80 -m string --string 'scanner' --algo kmp -j DROP
$IPTABLES -t raw -A PREROUTING -p tcp -m multiport --dports 80 -m string --string 'shodan' --algo kmp -j DROP

# Mitigate ICMP Floods
$IPTABLES -t raw -A PREROUNTING -p icmp --icmp-type address-mask-request -j DROP
$IPTABLES -t raw -A PREROUNTING -p icmp --icmp-type router-solicitation -j DROP
$IPTABLES -t raw -A PREROUNTING -p icmp --icmp-type timestamp-request -j DROP
$IPTABLES -t raw -A PREROUNTING -p icmp --icmp-type redirect -j DROP

# Drop SYN packets with source-port <1024 
$IPTABLES -t raw -I PREROUTING -p tcp --syn ! --sport 1024:65535 -m comment --comment "SYN: Invalid Source Port" -j DROP

# Drop all packets with invalid state
$IPTABLES -t mangle -I PREROUTING -p all -m conntrack --ctstate "$ST" -m comment --comment "Packet State Filter" -j DROP

# Malformed DNS FLOOD 
$IPTABLES -t raw -A PREROUTING -p udp --sport 53 -m string --string "Refused" --algo bm -j DROP
$IPTABLES -t raw -A PREROUTING -p udp --sport 53 -m string --string "0000000000000000" --algo bm -j DROP
$IPTABLES -t raw -A PREROUTING -p udp --sport 53 -m string --hex-string "|3000300030003000300030003000300030003000300030003000|" --algo bm -j DROP

# Prevent NTP reflect 
#$IPTABLES -t raw -A PREROUTING -p udp --dport 123 -m u32 --u32 "0>>22&0x3C@8&0xFF" -j DROP

# Patch some random attacks
#$IPTABLES -t raw -A PREROUTING -p tcp --syn -m u32 --u32 "0>>22&0x3C@12>>26&0x3F=0" -j DROP

# Drop SSL ( use TLS ) 
$IPTABLES -A INPUT -i $LAN -p tcp --dport 443 -m string --string "SSL" --algo bm -j DROP

# Drop SIP scans
$IPTABLES -A INPUT -i $LAN -p udp --dport 5060 -m string --string "sipvicious" --algo bm -j DROP
$IPTABLES -A INPUT -i $LAN -p udp --dport 5060 -m string --string "friendly-scanner" --algo bm -j DROP


# Drop SMTP with malicious payload 
$IPTABLES -t raw -A PREROUTING -p tcp --dport 25 -m string --string "HELO" --algo bm --to 65535 -j DROP
$IPTABLES -t raw -A PREROUTING -p tcp --dport 25 -m string --string "EHLO" --algo bm --to 65535 -j DROP

# Drop packages with bittorrrent amplification
$IPTABLES -t raw -A PREROUTING -m string --string "Torrent" --algo bm -j DROP

# Drop FTP with malicious payload
$IPTABLES  -t raw -A PREROUTING -p tcp --dport 21 -m string --string "SITE EXEC" --algo bm -j DROP

# Drop DNS recursive attacks
$IPTABLES -t raw -A PREROUTING -p udp --dport 53 -m string --string "recursion" --algo bm -j DROP
$IPTABLES -t raw -A PREROUTING -p tcp --dport 53 -m string --hex-string "|0d 0a 0d 0a|" --algo bm -j DROP

# Drop DNS/NTP that are not 
$IPTABLES -t raw -A PREROUTING -p udp --dport 53  -m string ! --string "DNS" --algo bm --to 65535 -j ACCEPT
$IPTABLES -t raw -A PREROUTING -p udp --dport 123 -m string ! --string "NTP" --algo bm --to 65535 -j ACCEPT

# Drop Heartbleed attacks
$IPTABLES -t raw -A PREROUTING -p tcp --dport 80 -m u32 --u32 "52=0x18030000 && 56=0x00000000" -j DROP
$IPTABLES -t raw -A PREROUTING -p tcp --dport 80 -m string --algo bm --string '() {' -j DROP

# Patch against some wierd attacks
$IPTABLES -t raw -A PREROUTING -p icmp --icmp-type 3/4 -j DROP

# Block 0 TTLs 
$IPTABLES -t raw -A PREROUTING -m ttl --ttl-eq 0 -j DROP

# Allow Packages with correct length 
$IPTABLES -t raw -A PREROUTING -p tcp -m length ! --length 40:1500 -j DROP
$IPTABLES -t raw -A PREROUTING -p udp -m length ! --length 20:1500 -j DROP
$IPTABLES -t raw -A PREROUTING -p icmp -m length ! --length 64:72 -j DROP

# Drop TFO packages 
#$IPTABLES -t raw -A PREROUTING -p tcp --syn -m u32 --u32 "12&0xFFFF=0x0" -j DROP

# Block 0 and 1 source-port 
$IPTABLES -t raw -A PREROUTING -p tcp -m multiport --sports 0,1 -j DROP
$IPTABLES -t raw -A PREROUTING -p udp -m multiport --sports 0,1 -j DROP

# Against TCP bypasses
#$IPTABLES -t raw -A PREROUTING -p tcp -m tcp --tcp-flags ACK ACK -m hashlimit --hashlimit-mode srcip --hashlimit-name ackflood --hashlimit-above 1000/s --hashlimit-burst 2 -j DROP
#$IPTABLES -t raw -A PREROUTING -p tcp -m tcp --tcp-flags ACK,PSH ACK,PSH -m hashlimit --hashlimit-mode srcip --hashlimit-name ackpshflood --hashlimit-above 1000/s --hashlimit-burst 2 -j DROP

# Filter by None status
$IPTABLES -t mangle -A PREROUTING -p all -m conntrack --ctstatus NONE -j DROP

# Netbios for Windows Machines
$IPTABLES -A INPUT -i $LAN -p udp -m udp --dport 137 -j DROP
$IPTABLES -A INPUT -i $LAN -p tcp -m tcp --dport 137 -j DROP
$IPTABLES -A INPUT -i $LAN -p udp -m udp --dport 138 -j DROP
$IPTABLES -A INPUT -i $LAN -p tcp -m tcp --dport 138 -j DROP

# DHCP Service ? ( No ... we don't use DHCP ) 
$IPTABLES -A INPUT -i $LAN -p udp -m udp --dport 67 -j DROP
$IPTABLES -A INPUT -i $LAN -p udp -m udp --dport 68 -j DROP

# Ignore Multicast
$IPTABLES -A INPUT -i $LAN -s 224.0.0.0/8 -j DROP

# Ignore BroadCast 
$IPTABLES -A INPUT -i $LAN -d 0.0.0.0 -j DROP
$IPTABLES -A INPUT -i $LAN -d 255.255.255.255 -j DROP

# Ignorar pacotes inválidos 
$IPTABLES -A INPUT -i $LAN -m conntrack --ctstate INVALID -j DROP

# UPnP Connections from Router must be denied 
$IPTABLES -A INPUT -i $LAN -p udp -m udp --dport 1900 -j LOG --log-prefix "UPnP Connections: " --log-level 7
$IPTABLES -A INPUT -i $LAN -p udp -m udp --dport 1900 -j DROP 

# To relieve server load during UDP Floods, restrict the outgoing ICMP 'Port-Unreach' packets per second (PPS).
# # ----------------------------------------------------------------
"$IPTABLES" -t raw -A OUTPUT -o $LAN -p icmp --icmp-type port-unreach -m limit --limit "$OPL" --limit-burst 2 -j ACCEPT
"$IPTABLES" -t raw -A OUTPUT -o $LAN -p icmp --icmp-type port-unreach -j DROP
# LOG Stuff 
#$IPTABLES -A INPUT -i $LAN -m limit --limit 5/min -j LOG --log-prefix "Communication Logged " --log-level 7
$IPTABLES -A FORWARD -m limit --limit 5/min -j LOG --log-prefix "Communication Logged " --log-level 7
#$IPTABLES -A OUTPUT -o $LAN -m limit --limit 5/min -j LOG --log-prefix "Communication Logged " --log-level 7

# IPSET 
# ipset -q flush ipsum
# ipset -q create ipsum hash:ip
# for ip in $(curl https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt 2>/dev/null | grep -v "#" | grep -v -E "\s[1-2]$" | cut -f 1);  do ipset add ipsum $ip; done
# $IPTABLES -D INPUT -i $LAN -m set --match-set ipsum src -j DROP 2>/dev/null
# $IPTABLES -I INPUT -i $LAN -m set --match-set ipsum src -j DROP

# I AM A DESKTOP behind a ROuter 
$IPTABLES -A INPUT -i $LAN -p tcp -m tcp -m state --state ESTABLISHED -j ACCEPT 
$IPTABLES -A FORWARD -j DROP
$IPTABLES -A OUTPUT -o $LAN -p tcp -m tcp -m state --state NEW -j ACCEPT 
