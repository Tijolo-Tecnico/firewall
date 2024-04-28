#!/bin/bash
# autor: Oscar FM
# Firewall personalizada para "Tijolo Técnico" 
# Esta máquina tem o IP dinâmico para a WAN e IP estático para a LAN 
# Esta máquina tem o Debian instalado
# Nota: Instalar ( apt install iptables-persistence ) 
 
# IPTables Command 
IPTables="/usr/sbin/iptables"
IPTSave="/usr/sbin/iptables-save > /etc/iptables/rules.v4"

# DNS da máquina da WAN  
DNS1="192.168.1.68"
DNS2="192.168.1.254"

# DNS público
DNS3="1.1.1.1"
DNS4="8.8.8.8"

# Network Cards 
LOOPBACK="127.0.0.1/8"
WAN="enp3s0f0"
LAN="enp3s0f1"

# Flush: apagar todas as regras anteriores
$IPTables -F
$IPTables -X 
$IPTables -Z 

$IPTables -t nat -F 
$IPTables -t nat -X 
$IPTables -t mangle -F
$IPTables -t mangle -X 
$IPTables -t raw -F 
$IPTables -t raw -X 

# Negar todo o tráfico 
$IPTables -P INPUT DROP
$IPTables -P FORWARD DROP
$IPTables -P OUTPUT DROP

# #Aceita conecções da placa local mas rejeita pacotes que declarem terem origem na placa local
$IPTables -A INPUT -i lo -p tcp --syn -s 127.0.0.1/255.0.0.0 -j ACCEPT
$IPTables -A OUTPUT -i lo -p tcp --syn -s 127.0.0.1/255.0.0.0 -j ACCEPT
$IPTables -A INPUT -s $LOOPBACK ! -i lo -j DROP 

# Aceitar o comando PING desde o Computador pessoal para a Firewall mas limita a 1s por cada ping 
# Isto para evitar possíveis reconhecimentos de Máquina e outros ataques tal como o Denial of Service  
$IPTables -A INPUT -i $LAN -p icmp --icmp-type echo-request -m limit 1/s -j ACCEPT 

# Aceitar saidas de procura de DNS 
# DNS 1 
$IPTables -A OUTPUT -o $LAN -p udp -s $WAN -d $DNS1 --sport 49152:65535 --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT
$IPTables -A INPUT -i $LAN -p udp -s $DNS1 -d $WAN --sport 49152:65535 --dport 53 -m state --state ESTABLISHED -j ACCEPT 
# DNS 2 
$IPTables -A OUTPUT -o $LAN -p udp -s $WAN -d $DNS2 --sport 49152:65535 --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT
$IPTables -A INPUT -i $LAN -p udp -s $DNS2 -d $WAN --sport 49152:65535 --dport 53 -m state --state ESTABLISHED -j ACCEPT 
# DNS 3  
$IPTables -A OUTPUT -o $LAN -p udp -s $WAN -d $DNS3 --sport 49152:65535 --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT
$IPTables -A INPUT -i $LAN -p udp -s $DNS3 -d $WAN --sport 49152:65535 --dport 53 -m state --state ESTABLISHED -j ACCEPT
# DNS 4
$IPTables -A OUTPUT -o $LAN -p udp -s $WAN -d $DNS4 --sport 49152:65535 --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT
$IPTables -A INPUT -i $LAN -p udp -s $DNS4 -d $WAN --sport 49152:65535 --dport 53 -m state --state ESTABLISHED -j ACCEPT 

# Aceitar ligação externas para fazer o update, ou instalar software usando o comando apt 
$IPTables -A OUTPUT -o $LAN -p tcp -m tcp -s $WAN --sport 49152:65535 -d 0/0 --dport 80 -m state --state NEW,ESTABLISHED -j ACCEPT
$IPTables -A INPUT -i $LAN -p tcp -s 0/0 -d $WAN --sport 80 --dport 49152:65535 -m state --state ESTABLISHED -j ACCEPT 
$IPTables -A OUTPUT -o $LAN -p tcp -m tcp -s $WAN --sport 49152:65535 -d 0/0 --dport 443 -m state --state NEW,ESTABLISHED -j ACCEPT
$IPTables -A INPUT -i $LAN -p tcp -s 0/0 -d $WAN --sport 443 --dport 49152:65535 -m state --state ESTABLISHED -j ACCEPT 

# Aceita ligações de SSH a partir do computador pessoal ( só e mais nenhum ) 
$IPTables -A INPUT -p tcp -s 10.0.0.101 --dport 22 -m conntrack --ctstate NEW,ESTRABLISHED -j LOG 
$IPTables -A INPUT -p tcp -s 10.0.0.101 --dport 22 -m conntrack --ctstate NEW,ESTRABLISHED -j ACCEPT 
$IPTables -A OUTPUT -p tcp --sport 22 -m conntrack --ctstate ESTABLISHED -j LOG
$IPTables -A OUTPUT -p tcp --sport 22 -m conntrack --ctstate ESTABLISHED -j ACCEPT 

# Aceita ligações para o Webmin a partir do computador pessoa ( só e mais nenhum ) 
#$IPTables -A INPUT -p tcp -s 10.0.0.101 --dport 10000 -m conntrack --ctstate NEW,ESTRABLISHED -j ACCEPT 
#$IPTables -A OUTPUT -p tcp --sport 10000 -m conntrack --ctstate ESTABLISHED -j ACCEPT 

# Preparar para redireccionar tráfico: 
echo "1" > /proc/sys/net/ipv4/ip_forward 

# re-direccionamento do tráfico ( desde rede local para rede externa ) 
$IPTables -t nat -A POSTROUTING -o $WAN -j MASQUERADE 
$IPTables -A FORWARD -i $WAN -o $LAN -m state --state RELATED,ESTRABLISHED -j ACCEPT 
$IPTables -A FORWARD -i $LAN -o $WAN -j ACCEPT 

# Proteção de scans: proibir scans 
$IPTables -N port-scanning
$IPTables -A port-scanning -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 1/s --limit-burst 2 -j RETURN
$IPTables -A port-scanning -j LOG
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
$IPTables -A INPUT -p tcp ! --syn -m state --state NEW -j LOG
$IPTables -A INPUT -p tcp ! --syn -m state --state NEW -j DROP

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

# Ignorar pacotes inválidos 
$IPTables -A INPUT -m conntrack --ctstate INVALID -j DROP

# Confirma que "deixamos cair tudo"
$IPTables -A INPUT -j LOG --log-prefix'**INPUT DROPED**'
$IPTables -A INPUT -j DROP 
$IPTables -A OUTPUT -j DROP 

# Salvar regras 
$IPTSave
