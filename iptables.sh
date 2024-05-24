#!/bin/bash
# autor: Oscar FM
# Firewall personalizada para "Tijolo Técnico" 
# Esta máquina tem o IP dinâmico para a WAN e IP estático para a LAN 
# Esta máquina tem o Debian instalado
# Nota: Instalar ( apt install iptables-persistence ) 
 
# IPTABLES Command 
IPTABLES="/usr/sbin/iptables"
IPTSave="/usr/sbin/iptables-save > /etc/iptables/rules.v4"

# DNS da máquina da WAN  
#DNS1="192.168.1.68"
#DNS2="192.168.1.254"

# DNS público
DNS3="1.1.1.1"
#DNS4="8.8.8.8"

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
#$IPTABLES -A INPUT -p icmp -j DROP
#$IPTABLES -A INPUT -i $LAN -p icmp --icmp-type echo-request -m limit 1/s -j ACCEPT 
#$IPTABLES -A INPUT -p icmp -m state --state NEW --icmp-type 8 -j ACCEPT 
#$IPTABLES -A OUTPUT -o $LAN -p icmp -m state --state NEW --icmp-type 8 -j ACCEPT 

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
$IPTABLES -A OUTPUT -o $LAN -p tcp -m tcp --dport 443 -m state --state NEW -j ACCEPT
$IPTABLES -A INPUT -i $LAN -p tcp -m tcp --dport 80 -m state --state ESTABLISHED -j ACCEPT
$IPTABLES -A INPUT -i $LAN -p tcp -m tcp --dport 443 -m state --state ESTABLISHED -j ACCEPT

# Accept thunderbird  ( email Client ) 
$IPTABLES -A OUTPUT -o $LAN -p tcp -m tcp --dport 993 -m state --state NEW -j ACCEPT
$IPTABLES -A INPUT -i $LAN -p tcp -m tcp --dport 993 -m state --state ESTABLISHED -j ACCEPT

# TOR network and Privoxy 
$IPTABLES -A OUTPUT -o $LAN -p tcp -m tcp --dport 8080 -m state --state NEW -j ACCEPT
$IPTABLES -A INPUT -i $LAN -p tcp -m tcp --dport 8080 -m state --state ESTABLISHED -j ACCEPT

$IPTABLES -A OUTPUT -o $LAN -p tcp -m tcp --dport 9050 -m state --state NEW -j ACCEPT
$IPTABLES -A INPUT -i $LAN -p tcp -m tcp --dport 9050 -m state --state ESTABLISHED -j ACCEPT

$IPTABLES -A OUTPUT -o $LAN -p tcp -m tcp --dport 8118 -m state --state NEW -j ACCEPT
$IPTABLES -A INPUT -i $LAN -p tcp -m tcp --dport 8118 -m state --state ESTABLISHED -j ACCEPT

# LOG 
#$IPTABLES -A OUTPUT -o $LAN -p tcp -m tcp --dport 80 -m state --state NEW -j LOG --log-prefix "iptables_OUTPUT_log: " --log-level 7
#$IPTABLES -A INPUT -i $LAN -p tcp -m tcp --dport 80 -m state --state ESTABLISHED -j LOG --log-prefix "iptables_INPUT_log: " --log-level 7
# ACCEPT
#$IPTABLES -A OUTPUT -o $LAN -p tcp -m tcp --dport 80 -m state --state NEW -m comment --comment "Allow Public Web Access" -j ACCEPT 
#$IPTABLES -A INPUT -i $LAN -p tcp  -m tcp --sport 80 -m state --state ESTABLISHED -m comment --comment "Allow Public Web Access" -j ACCEPT
# LOG 
#$IPTABLES -A OUTPUT -o $LAN -p tcp -m tcp --dport 443 -m state --state NEW -j LOG --log-prefix "iptables_OUTPUT_log: " --log-level 7
#$IPTABLES -A INPUT -i $LAN -p tcp -m tcp --dport 443 -m state --state ESTABLISHED -j LOG --log-prefix "iptables_INPUT_log: " --log-level 7
# ACCEPT 
#$IPTABLES -A OUTPUT -o $LAN -p tcp -m tcp --dport 587 -m state --state NEW -m comment --comment "Allow Public Secure Web Access" -j ACCEPT 
#$IPTABLES -A INPUT -i $LAN -p tcp -m tcp --sport 587 -m state --state ESTABLISHED -m comment --comment "Allow Public Secure Web Access" -j ACCEPT 

# Aceitar ligação externas para fazer o update, ou instalar software usando o comando apt com duas placas de rede
# $IPTABLES -a OUTPUT -o $LAN -p tcp -m tcp -s $wan --sport 49152:65535 -d 0/0 --dport 80 -m state --state new,established -j ACCEPT
# $IPTABLES -a INPUT -i $LAN -p tcp -s 0/0 -d $wan --sport 80 --dport 49152:65535 -m state --state established -j ACCEPT 
# $IPTABLES -a OUTPUT -o $LAN -p tcp -m tcp -s $wan --sport 49152:65535 -d 0/0 --dport 443 -m state --state new,established -j ACCEPT
# $IPTABLES -a INPUT -i $LAN -p tcp -s 0/0 -d $wan --sport 443 --dport 49152:65535 -m state --state established -j ACCEPT 

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

# Proteção de scans: proibir scans 
#$IPTABLES -N port-scanning
#$IPTABLES -A port-scanning -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 1/s --limit-burst 2 -j RETURN
#$IPTABLES -A port-scanning -j LOG
#$IPTABLES -A port-scanning -j DROP

# Syn-Flood Protection
#$IPTABLES -N syn_flood
#$IPTABLES -A INPUT -p tcp --syn -j syn_flood
#$IPTABLES -A syn_flood -m limit --limit 1/s --limit-burst 3 -j RETURN
#$IPTABLES -A syn_flood -j DROP
#$IPTABLES -A INPUT -p icmp -m limit --limit  1/s --limit-burst 1 -j ACCEPT
#$IPTABLES -A INPUT -p icmp -m limit --limit 1/s --limit-burst 1 -j LOG --log-prefix PING-DROP:

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
$IPTABLES -A INPUT -m conntrack --ctstate INVALID -j DROP

# UPnP Connections from Router must be denied 
$IPTABLES -A INPUT -i $LAN -p udp -m udp --dport 1900 -j LOG --log-prefix "UPnP Connections: " --log-level 7
$IPTABLES -A INPUT -i $LAN -p udp -m udp --dport 1900 -j DROP 

# LOG Stuff 
#$IPTABLES -A INPUT -i $LAN -m limit --limit 5/min -j LOG --log-prefix "Communication Logged " --log-level 7
$IPTABLES -A FORWARD -m limit --limit 5/min -j LOG --log-prefix "Communication Logged " --log-level 7
#$IPTABLES -A OUTPUT -o $LAN -m limit --limit 5/min -j LOG --log-prefix "Communication Logged " --log-level 7

# I AM A DESKTOP behind a ROuter 
$IPTABLES -A INPUT -i $LAN -p tcp -m tcp -m state --state ESTABLISHED -j ACCEPT 
$IPTABLES -A FORWARD -j DROP
$IPTABLES -A OUTPUT -o $LAN -p tcp -m tcp -m state --state NEW -j ACCEPT 
