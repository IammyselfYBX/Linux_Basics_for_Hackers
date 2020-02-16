#! /bin/bash

# This script is designed to find hosts with MySQL installed

nmap -sT 192.168.181.0/24-p 3306 >/dev/null -oG MYSQLscan

cat MYSQLscan | grep open > MYSQLScan2

cat MYSQLScan2

