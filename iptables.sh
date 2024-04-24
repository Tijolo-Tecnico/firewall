#!/bin/bash
# Firewall Script 
# Oscar FM

# IPTables Command 
IPTables="/usr/sbin/iptables"
IPTSave="/usr/sbin/iptables-save"

# Network Cards 
WAN="enp3s0f0"
LAN="enp3s0f1"

# Primeiro passo: Aceitar o tráfico 
$IPTables -P INPUT ACCEPT
$IPTables -P FORWARD ACCEPT
$IPTables -P OUTPUT ACCEPT

# Flush 
$IPTables -F
$IPTables -X 
$IPTables -Z 

$IPTables -t nat -F 
$IPTables -t nat -X 
$IPTables -t mangle -F
$IPTables -t mangle -X 
$IPTables -t raw -F 
$IPTables -t raw -X 

# Preparar para redireccionar tráfico: 
echo 1 > /proc/sys/net/ipv4/ip_forward 

# Servidor Firewall 
# #Aceita conecções da placa local 
$IPTables -A INPUT -i lo -j ACCEPT

# Aceita ligações de SSH a partir do computador pessoal ( só e mais nenhum ) 
# $IPTables -A INPUT -p tcp --dport 22 -j ACCEPT 
$IPTables -A INPUT -p tcp -s 10.0.0.101 --dport 22 -m conntrack --ctstate NEW,ESTRABLISHED -j ACCEPT 
$IPTables -A OUTPUT -p tcp --sport 22 -m conntrack --ctstate ESTABLISHED -j ACCEPT 

# Aceita ligações para o Webmin
$IPTables -A INPUT -p tcp --dport 10000 -j ACCEPT 

# Aceita ligações do computador pessoal 
#$IPTables -A INPUT -s 10.0.0.101 -j ACCEPT 

# Direccionamento do tráfico 
$IPTables -t nat -A POSTROUTING -o $WAN -j MASQUERADE 
$IPTables -A FORWARD -i $WAN -o $LAN -m state --state RELATED,ESTRABLISHED -j ACCEPT 
$IPTables -A FORWARD -i $LAN -o $WAN -j ACCEPT 

# Aceitar o comando PING desde o Computador pessoal para a Firewall 
$IPTables -A INPUT -i $LAN -p icmp --icmp-type echo-request -j ACCEPT 

# Ignorar pacotes inválidos 
$IPTables -A INPUT -m conntrack --ctstate INVALID -j DROP

# Proteção de scans: proibir scans 
$IPTables -N port-scanning
$IPTables -A port-scanning -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 1/s --limit-burst 2 -j RETURN
$IPTables -A port-scanning -j DROP

# Syn-Flood Protection
$IPTables -N syn_flood
$IPTables -A INPUT -p tcp --syn -j syn_flood
$IPTables -A syn_flood -m limit --limit 1/s --limit-burst 3 -j RETURN
$IPTables -A syn_flood -j DROP
$IPTables -A INPUT -p icmp -m limit --limit  1/s --limit-burst 1 -j ACCEPT
$IPTables -A INPUT -p icmp -m limit --limit 1/s --limit-burst 1 -j LOG --log-prefix PING-DROP:
$IPTables -A INPUT -p icmp -j DROP
$IPTables -A OUTPUT -p icmp -j ACCEPT

# Block packages that are not SYN 
$IPTables -A INPUT -p tcp ! --syn -m state --state NEW -j DROP
$IPTables 
# Block with Bogus Flags 
$IPTables  -t mangle -A PREROUTING -p tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -j DROP
$IPTables  -t mangle -A PREROUTING -p tcp --tcp-flags FIN,SYN FIN,SYN -j DROP
$IPTables  -t mangle -A PREROUTING -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
$IPTables  -t mangle -A PREROUTING -p tcp --tcp-flags FIN,RST FIN,RST -j DROP
$IPTables  -t mangle -A PREROUTING -p tcp --tcp-flags FIN,ACK FIN -j DROP
$IPTables  -t mangle -A PREROUTING -p tcp --tcp-flags ACK,URG URG -j DROP
$IPTables  -t mangle -A PREROUTING -p tcp --tcp-flags ACK,FIN FIN -j DROP
$IPTables  -t mangle -A PREROUTING -p tcp --tcp-flags ACK,PSH PSH -j DROP
$IPTables  -t mangle -A PREROUTING -p tcp --tcp-flags ALL ALL -j DROP
$IPTables  -t mangle -A PREROUTING -p tcp --tcp-flags ALL NONE -j DROP
$IPTables  -t mangle -A PREROUTING -p tcp --tcp-flags ALL FIN,PSH,URG -j DROP
$IPTables  -t mangle -A PREROUTING -p tcp --tcp-flags ALL SYN,FIN,PSH,URG -j DROP
$IPTables -t mangle -A PREROUTING -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP

# Salvar regras 
$IPTSave
