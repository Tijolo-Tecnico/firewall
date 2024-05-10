#!/bin/bash
# IF you are using another domain to push your code... 

pkill -x ssh-agent 
sleep 1
echo "ssh-agents killed"
eval $(ssh-agent)
sleep 1 
echo "ssh-agent inicialized"
ssh-add ~/.ssh/tijolo
sleep 1
echo "ssh-key-id added"
git add . 
echo "all changes added to commit state"
git commit -m "Melhoria do ficheiro"
git push git@github.com:Tijolo-Tecnico/firewall
echo "Push completed"
sleep 3
