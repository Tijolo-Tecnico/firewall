#!/bin/bash 
# iptables Script for machine with dual network Card
# Tijolo Técnico - Firewall Config

# IPTables location 
ipt="/usr/sbin/iptables"

# Loopback - local network card 
lback="127.0.0.1/8"

# Network Cards names
lan="enp3s0f0" # LAN: Rede Interna
wan="enp3s0f1" # WAN: Rede externa 

# Clear IPTables rules 
$ipt -F
$ipt -X
$ipt -Z

# Clear IPTables NAT Rules 
$ipt -t nat -F 
$ipt -t nat -X
$ipt -t nat -Z 

# Clear IPTables MANGLE Rules 
$ipt -t mangle -F
$ipt -t mangle -X
$ipt -t mangle -Z

# Clear IPTables RAW Rules 
$ipt -t raw -F 
$ipt -t raw -X
$ipt -t raw -Z

# Define Default IPTables Policy to ACCEPT 
$ipt --policy INPUT ACCEPT 
$ipt --policy FORWARD ACCEPT 
$ipt --policy OUTPUT ACCEPT 

# Sucicata Instalado? 
# $ipt -I INPUT -i $lan -j NFQUEUE
# $ipt -I INPUT -i $wan -j NFQUEUE
# $ipt -I OUTPUT -o $lan -j NFQUEUE
# $ipt -I OUTPUT -o $wan -j NFQUEUE
# $ipt -I FORWARD -j NFQUEUE


# Acept connections from local network-card but drop all that have the same source 
$ipt -A INPUT -i lo -p tcp -m tcp --syn -s 127.0.0.1/255.0.0.0 -j ACCEPT
$ipt -A OUTPUT -o lo -p tcp -m tcp --syn -s 127.0.0.1/255.0.0.0 -j ACCEPT 
$ipt -A INPUT -s $lback ! -i lo -j DROP 

# Preparar para redireccionamento do tráfico
echo "1" > /proc/sys/net/ipv4/ip_forward

# Redireccionamento do tráfico desde a LAN para a WAN 
$ipt -t nat -A POSTROUTING -o $wan -j MASQUERADE 
$ipt -A FORWARD -i $wan -o $lan -m state --state ESTABLISHED -j ACCEPT 
$ipt -A FORWARD -i $lan -o $wan -m state --state NEW -j ACCEPT

# A WAN não recebe ligações do Exterior que não tenham sido feitas pela LAN 
$ipt -A INPUT -i $wan -p tcp -m tcp -m state --state NEW -j LOG --log-prefix "Communication Droped" --log-level 7 
$ipt -A INPUT -i $wan -p tcp -m tcp -m state --state NEW -j DROP 

# Aceita ligações Novas da LAN para a WAN e limita o tráfico às novas ligações 

# Aceita chamadas de DNS 
$ipt -A OUTPUT -o $lan -p tcp -m tcp --dport 53 -m state --state NEW -m comment --comment "DNS call Allowed" -j ACCEPT 
$ipt -A INPUT -i $lan -p tcp -m tcp --dport 53 -m state --state ESTABLISHED -m comment --comment "DNS call Allowed" -j ACCEPT

# Configuração de clientes de Email ( Usar o Thunderbird ) 
$ipt -A OUTPUT -o $lan -p tcp -m tcp --dport 993 -m state --state NEW -m comment --comment "Email Session Allowed" -j ACCEPT 
$ipt -A INPUT -i $lan -p tcp -m tcp --dport 993 -m state --state ESTABLISHED -m comment --comment "Email Session Allowed" -j ACCEPT

# Usar o navegador Web 
$ipt -A OUTPUT -o $lan -p tcp -m tcp --dport 80 -m state --state NEW -m comment --comment "Web Session Allowed" -j ACCEPT 
$ipt -A INPUT -i $lan -p tcp -m tcp --dport 80 -m state --state ESTABLISHED -m comment --comment "Web Session Allowed" -j ACCEPT
$ipt -A OUTPUT -o $lan -p tcp -m tcp --dport 443 -m state --state NEW -m comment --comment "Web Session Allowed" -j ACCEPT 
$ipt -A INPUT -i $lan -p tcp -m tcp --dport 443 -m state --state ESTABLISHED -m comment --comment "Web Session Allowed" -j ACCEPT

# Aceitar ligações por SSH a partir da LAN 
$ipt -A OUTPUT -o $lan -p tcp -m tcp --dport 22 -m state --state NEW -m comment --comment "Secure Session Allowed" -j ACCEPT 
$ipt -A INPUT -i $lan -p tcp -m tcp --dport 22 -m state --state ESTABLISHED -m comment --comment "Secure Session Allowed" -j ACCEPT
$ipt -A INPUT -i $lan -p tcp -m tcp --syn --dport 22 -m connlimit --connlimit-above 3 -j REJECT # Não aceita mais do que 3 sessões ao mesmo tempo

# Block packages that are not SYN but log them 
$ipt -A INPUT -i $lan -p tcp -m tcp ! --syn -m state --state NEW -j LOG --log-prefix "Droped: Invalid Packages " --log-level 7 
$ipt -A INPUT -i $lan -p tcp -m tcp ! --syn -m state --state NEW -j DROP

# Ignore Invalid Packages but log them 
$ipt -A INPUT -m conntrack --ctstate INVALID -j LOG --log-prefix "Droped: Invalid Packages " --log-level 7 
$ipt -A INPUT -m conntrack --ctstate INVALID -j DROP

# Against crazy Flags 
$ipt -t mangle -A PREROUNTING -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK,FIN,URG NONE -j DROP
$ipt -t mangle -A PREROUNTING -p tcp -m tcp --tcp-flags FIN,SYN FIN,SYN -j DROP
$ipt -t mangle -A PREROUNTING -p tcp -m tcp --tcp-flags FIN,RST SYN,RST -j DROP
$ipt -t mangle -A PREROUNTING -p tcp -m tcp --tcp-flags FIN,ACK FIN -j DROP
$ipt -t mangle -A PREROUNTING -p tcp -m tcp --tcp-flags ACK,URG FIN -j DROP
$ipt -t mangle -A PREROUNTING -p tcp -m tcp --tcp-flags ACK,FIN FIN -j DROP
$ipt -t mangle -A PREROUNTING -p tcp -m tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP
$ipt -t mangle -A PREROUNTING -p tcp -m tcp --tcp-flags ALL SYN,FIN,PSH,URG -j DROP
$ipt -t mangle -A PREROUNTING -p tcp -m tcp --tcp-flags ALL FIN,PSH,URG -j DROP
$ipt -t mangle -A PREROUNTING -p tcp -m tcp --tcp-flags ALL NONE -j DROP
$ipt -t mangle -A PREROUNTING -p tcp -m tcp --tcp-flags ALL ALL -j DROP

# Log everything else 
$ipt -A INPUT -i $lan -j LOG --log-prefix "logged for security reasons" --log-level 7 
$ipt -A FORWARD -j LOG --log-prefix "logged for security reasons" --log-level 7 
$ipt -A OUTPUT -o $lan -j LOG --log-prefix "logged for security reasons" --log-level 7 

# Ensure Policy 
$ipt -A INPUT -i $lan -p tcp -m tcp -m state --state ESTABLISHED -j ACCEPT 
$ipt -A FORWARD -j ACCEPT 
$ipt -A OUTPUT -o $lan -p tcp -m tcp -m state --state NEW -j ACCEPT 
