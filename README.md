UDR
===

UDR is a wrapper around rsync that enables rsync to use UDT.

CONTENT
-------
./src:     UDR source code
./udt:	   UDT source code, documentation and license

TO MAKE
------- 
    make -e os=XXX arch=YYY 

XXX: [LINUX(default), BSD, OSX]   
YYY: [IA32(default), POWERPC, IA64, AMD64]  

### Dependencies:
OpenSSL (libssl and libcrypto)  
Currently, UDR has mainly been tested on Linux so your mileage may vary on another OS. UDT has been well tested on all of the provided options.

USAGE
------
UDR must be on the client and server machines that data will be transferred between. UDR uses ssh to do authentication and automatically start the server-side UDR process. At least one UDP port needs to be open between the machines, by default UDR starts with port 9000 and looks for an open port up to 9100, changing this is an option. Encryption is off by default. When turned on encryption uses the OpenSSL implementation of blowfish. Currently, encryption appears to reduce the speed by about half, this should be improved in future versions. 

### Basic usage:
    udr [udr options] rsync [rsync options] src dest

### UDR options: 
[-a starting port number] default is 9000  
[-b ending port number] default is 9100  
[-n] turns on encryption  
[-p path] local path for the .udr_key file used for encryption, default is the current directory   
[-c remote udr location] by default udr assumes that udr is in your path on the remote system, here you can specify the location explicitly  
[-v] verbose mode, typically for debugging purposes  
[--version] print out the version  

The rsync [rsync options] should take any of the standard rsync options.

### A basic example command:
    udr rsync -av --stats --progress /home/user/tmp/ hostname.com:/home/user/tmp

### A command with udr options:
    udr -c /home/user/udr/src/udr -a 8000 -b 8010 rsync -av --stats --progress /home/user/tmp/ hostname.com:/home/user/tmp

### Notes:
After the rsync data transfer is complete, the local udr thread is shutdown by a signal. Rsync thinks this is abnormal and prints out the error "rsync error: sibling process terminated abnormally", which can be ignored. However, the transfer should be complete, if other rsync errors appear these are true errors.

UDR SERVER (beta)
----------
The server functionality is incomplete, but here's how it works currently for testing purposes. The UDR server allows UDR transfers for users without accounts. The UDR server is started by using the -d option which takes as an argument the path that contains the files to be served out. The server does not support encryption, so options related to encryption are not valid. By default the server listens on TCP port 3490, which can be changed by using [-o port number]. 

### Basic server usage:
    udr -d /path/to/files [udr server options] rsync

### Connecting to the UDR server
To connect to the UDR server, use double colons instead of the single colon, similar to connecting to a rsync daemon. Listing files is also the same as with rsync.

### Basic example command for downloading from a UDR server:
    udr rsync -av --stats --progress hostname.com::path/to/files /home/user/target

### List files on server:
    udr rsync hostname.com::path/to/files /home/user/target



