#!/bin/bash 
# iptables Script for machine with dual network Card
# Tijolo Técnico - Firewall Config

# IPTables location 
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

# Ensure Policy 
$ipt -A INPUT -i $lan -p tcp -m tcp -m state --state ESTABLISHED -j ACCEPT 
$ipt -A FORWARD -j ACCEPT 
$ipt -A OUTPUT -o $lan -p tcp -m tcp -m state --state NEW -j ACCEPT 
