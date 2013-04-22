#!/bin/bash
# example:
# ./tune.sh 127.0.0.1 lacadmin /home/lacadmin/udr_crypto/udt/tuner/appserver /home/lacadmin/udr_crypto/udt/src

port=9000

host=$1
remote_user=$2
server_command=$3
remote_udt_path=$4

count=0
interval=60

settings_file=settings.txt
client=./appclient
export_ld="export LD_LIBRARY_PATH=$remote_udt_path"

while read line; do

    server_sysctl=$(echo $line|cut -f1 -d ,)
    client_sysctl=$(echo $line|cut -f2 -d ,)
    server_args=$(echo $line|cut -f3 -d ,)
    client_args=$(echo $line|cut -f4 -d ,)

    sudo sysctl -p $client_sysctl
    ssh $remote_user@$host "sudo sysctl -p $server_sysctl" <&-

    ssh $remote_user@$host "$export_ld; $server_command $port $server_args & pid=\$!;sleep $interval;kill \$pid" <&- &

    $client $host $port $client_args > raw_out_test$count &
    client_pid=$!

    sleep $interval
    kill $client_pid

    count=$((count+1))
done < $settings_file
