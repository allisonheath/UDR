UDR - trial beta version 0.1b - please do not distribute.

UDR is a wrapper around UDT that can be used with rsync.

CONTENT:
./src:     UDR source code
./udt:	   UDT source code, documentation and license

DEPENDENCIES:
OpenSSL (libssl and libcrypto)

TO MAKE: 
     make -e os=XXX arch=YYY 

XXX: [LINUX(default), BSD, OSX] 
YYY: [IA32(default), POWERPC, IA64, AMD64]

TO USE:
UDR must be on the client and server machines that data will be transferred between. UDR uses ssh to do authentication and automatically start the server-side UDR process. Encryption is on by default, using the OpenSSL implementation of blowfish. Currently, encryption appears to reduce the speed by about half, this should be improved in future versions. 

Basic usage:
udr [udr options] rsync [rsync options] src dest

UDR options:
[-v] verbose mode, typically for debugging purposes
[-p starting port number] default is 9000
[-q ending port number] default is 9100
[-n] turns off encryption
[-c remote udr location] by default udr assumes that udr is in your path on the remote system, here you can specify the location explicitly

The rsync [rsync options] should take any of the standard rsync options.

An example command:
 ./udr -c /home/aheath/projects/udr/src/udr rsync -av --stats --progress /home/aheath/tmp/ 192.168.1.102:/home/aheath/tmp2

Notes:
After the rsync data transfer is complete, the local udr thread is shutdown by a signal. Rsync thinks this is abnormal and prints out the error "rsync error: sibling process terminated abnormally", which can be ignored. However, the transfer should be complete, if other rsync errors appear these are true errors.



