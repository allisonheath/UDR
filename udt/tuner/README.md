UDT Tuner
===

This is a modification of udt/app/app(client/server) that takes cli args
along with a bash script that will run the client server pair with UDT and 
sysctl settings.

USAGE
------
Running the bash script tune.sh will read settings from the file settings.txt then as specified by cli args ssh to a remote host load a sysctl file and start the appserver with parameters from the local settings.txt.  Then tune.sh loads a local sysctl file and starts the appclient.  Both the server and client run for 1 minute and are then killed.  The output of appclient is writting to raw_out_testN where N is the line of settings.txt being run starting from 0.

### Basic usage:
    ./tune.sh 127.0.0.1 lacadmin /home/lacadmin/udr_crypto/udt/tuner/appserver /home/lacadmin/udr_crypto/udt/src

tune.sh will ssh to 127.0.0.1 as lacadmin then export LD_LIBRARY_PATH=/home/lacadmin/udr_crypto/udt/src then start /home/lacadmin/udr_crypto/udt/tuner/appserver

### Example settings.txt: 
	/etc/sysctl.conf,/etc/sysctl.conf,0 134217728 2097152 8900,0 134217728 2097152 8900 0
	/etc/sysctl.conf,/etc/sysctl.conf,1 134217728 2097152 8900,1 134217728 2097152 8900 10000

On the remote server run:
	sudo sysctl -p /etc/sysctl.conf
Then locally run:
	sudo sysctl -p /etc/sysctl.conf
Then remotely run:
	PATH_FROM_ARGS/appserver 9000 0 134217728 2097152 8900
Then locally:
	./appclient HOST_FROM_ARGS 9000 0 134217728 2097152 8900 0

0 means no blast congestion control. 134217728 is the UDT buffer size, 2097152 is the UDP buffer size, 8900 is the UDT MSS, and 0 is the blast rate.
