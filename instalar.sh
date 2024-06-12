#!/bin/bash 
#
cp ./etc/network/interfaces /etc/network/interfaces
cp ./etc/sysctl.conf /etc/sysctl.conf 
cp ./etc/resolv.conf /etc/resolv.conf
cp ./etc/hosts /etc/hosts 

chattr +i /etc/network/interfaces
chattr +i /etc/sysctl.conf
chattr +i /etc/hosts 
chattr +i /etc/resolv.conf

bash ./Correct_IPTables_Config.sh 
