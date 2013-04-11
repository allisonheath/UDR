/*****************************************************************************
Copyright 2013 Laboratory for Advanced Computing at the University of Chicago

This file is part of .

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions
and limitations under the License.
*****************************************************************************/

#include <unistd.h>
#include <cstdlib>
#include <cstring>
#include <netdb.h>
#include <iostream>
#include <udt.h>
#include <stdio.h>
#include "cc.h"
#include "udcat_common.h"

using std::cerr;
using std::endl;

int main(int argc, char* argv[])
{
    if ((3 != argc) || (0 == atoi(argv[2])))
    {
        cerr << "usage: appclient server_ip server_port" << endl;
        return 1;
    }

    UDT::startup();

    struct addrinfo hints, *local, *peer;

    memset(&hints, 0, sizeof(struct addrinfo));

    hints.ai_flags = AI_PASSIVE;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (0 != getaddrinfo(NULL, "9000", &hints, &local))
    {
        cerr << "incorrect network address.\n" << endl;
        return 1;
    }


    UDTSOCKET client = UDT::socket(local->ai_family, local->ai_socktype, local->ai_protocol);

    freeaddrinfo(local);

    if (0 != getaddrinfo(argv[1], argv[2], &hints, &peer))
    {
        cerr << "incorrect server/peer address. " << argv[1] << ":" << argv[2] << endl;
        return 1;
    }

    // connect to the server, implict bind
    if (UDT::ERROR == UDT::connect(client, peer->ai_addr, peer->ai_addrlen))
    {
        cerr << "connect: " << UDT::getlasterror().getErrorMessage() << endl;
        return 1;
    }

    pthread_t rcvthread;
    pthread_create(&rcvthread, NULL, recvdata, new UDTSOCKET(client));
    pthread_detach(rcvthread);

    freeaddrinfo(peer);

    size_t buf_size = 100000;
    int size;
    char* data = NULL;

    while ((size = getline(&data, &buf_size, stdin)) > 0) {
        int ssize = 0;
        int ss;
        while (ssize < size) {
            if (UDT::ERROR == (ss = UDT::send(client, data + ssize, size - ssize, 0))) {
                cerr << "send:" << UDT::getlasterror().getErrorMessage() << endl;
                break;
            }

            ssize += ss;
        }

        if (ssize < size)
            break;
    }

    UDT::close(client);

    free(data);

    UDT::cleanup();

    return 0;
}

