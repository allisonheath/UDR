#!/bin/bash
port=9000
host=$1
remote_user=$2

count=0
interval=30
settings_file=settings.txt
sever=$3
client=./appclient

# assumes the file has serverline\n clientline\n sysctl file
while read server_sysctl; do
    ssh $remote_user@$host "sudo sysctl -p $server_sysctl"

    read client_sysctl
    sudo sysctl -p $client_sysctl

    read server_line
    ssh $remote_user@$host "$server $port $server_line & pid=\$!;sleep $interval;kill \$pid"

    read client_line
    $client $host $port $client_line > raw_out_test$count &
    client_pid=$!

    sleep $interval

    kill $client_pid

    count=$((count+1))

done < $settings_file
