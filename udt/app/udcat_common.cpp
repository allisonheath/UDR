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
#include "udcat_common.h"

using std::cerr;
using std::endl;

void* recvdata(void* usocket)
{
    UDTSOCKET recver = *(UDTSOCKET*)usocket;
    delete (UDTSOCKET*)usocket;

    char* data;
    int size = BUF_SIZE;
    data = new char[size];

    while (true) {
        int rs;
        if (UDT::ERROR == (rs = UDT::recv(recver, data, size, 0))) {
            cerr << "recv:" << UDT::getlasterror().getErrorMessage() << endl;
            break;
        }

        write(fileno(stdout), data, rs);
    }

    delete [] data;

    UDT::close(recver);

    return NULL;
}


void* senddata(void* usocket)
{
    UDTSOCKET client = *(UDTSOCKET*)usocket;
    delete (UDTSOCKET*)usocket;

    char* data = NULL;
    size_t buf_size = BUF_SIZE;
    int size;

    while ((size = getline(&data, &buf_size, stdin)) > 0) {
       int ssize = 0;
       int ss;

       while (ssize < size) {
          if (UDT::ERROR == (ss = UDT::send(client, data + ssize, size - ssize, 0)))
          {
             cerr << "send:" << UDT::getlasterror().getErrorMessage() << endl;
             break;
          }

          ssize += ss;
       }

       if (ssize < size)
           break;
    }

    free(data);

    UDT::close(client);

    return NULL;
}

