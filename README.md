UDR - Development Version
=========================

UDR is a wrapper around rsync that enables rsync to use UDT.

CONTENT
-------
./src:     UDR source code
./udt:	   UDT source code, documentation and license

DEPENDENCIES
------------
OpenSSL (libssl and libcrypto)

TO MAKE: 
    make -e os=XXX arch=YYY 

XXX: [LINUX(default), BSD, OSX] 
YYY: [IA32(default), POWERPC, IA64, AMD64]

Currently, UDR has mainly been tested on Linux so your mileage may vary on another OS. UDT has been well tested on all of the provided options.

TO USE
------
UDR must be on the client and server machines that data will be transferred between. UDR uses ssh to do authentication and automatically start the server-side UDR process. At least one UDP port needs to be open between the machines, by default UDR starts with port 9000 and looks for an open port up to 9100, changing this is an option. Encryption is off by default. When turned on encryption uses the OpenSSL implementation of blowfish. Currently, encryption appears to reduce the speed by about half, this should be improved in future versions. 

### Basic usage:
udr [udr options] rsync [rsync options] src dest

### UDR options:
[-v] verbose mode, typically for debugging purposes  
[-a starting port number] default is 9000  
[-b ending port number] default is 9100  
[-n] turns on encryption  
[-p path] local path for the .udr_key file used for encryption, default is the current directory   
[-c remote udr location] by default udr assumes that udr is in your path on the remote system, here you can specify the location explicitly  

The rsync [rsync options] should take any of the standard rsync options.

### An example command:
 ./udr -c /home/aheath/projects/udr/src/udr rsync -av --stats --progress /home/aheath/tmp/ 192.168.1.102:/home/aheath/tmp2

### Notes:
After the rsync data transfer is complete, the local udr thread is shutdown by a signal. Rsync thinks this is abnormal and prints out the error "rsync error: sibling process terminated abnormally", which can be ignored. However, the transfer should be complete, if other rsync errors appear these are true errors.



