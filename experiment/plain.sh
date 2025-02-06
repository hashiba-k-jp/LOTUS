#!/bin/sh

expect -c "
set timeout -1
spawn python3 ../main.py
expect \"LOTUS >> \"
send \"import jpnic_network.yml\n\"
expect \"LOTUS >> \"
send \"run\n\"
expect \"LOTUS >> \"
send \"showASList sort best\n\"
expect \"LOTUS >> \"
send exit
exit 0
"
