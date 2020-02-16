#! /bin/bash

echo "Enter the Starting IP address :"
read FirstIP

echo "Enter the last octet of the last IP address : "
# the last octet is the last number(s) after the third period such as 255
read LastIP


echo "Enter the port number you want to scan for :"
read port


nmap -sT $FirstIP-$LastIP -p $port >/dev/null -oG MYSQLscan

cat MYSQLscan | grep open > MYSQLScan2

cat MYSQLScan2

