/*****************************************************************************
Copyright 2013 Laboratory for Advanced Computing at the University of Chicago

This file is part of TLS over UDT POC

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

#define _BSD_SOURCE 1
/* Or gethostname won't be declared properly on Linux and GNU platforms. */
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define USE_SOCKETS
#include "e_os.h"

#include <ctype.h>

#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/ssl.h>
#ifndef OPENSSL_NO_ENGINE
#include <openssl/engine.h>
#endif
#include <openssl/err.h>
#include <openssl/rand.h>
#ifndef OPENSSL_NO_RSA
#include <openssl/rsa.h>
#endif
#ifndef OPENSSL_NO_DSA
#include <openssl/dsa.h>
#endif
#include <openssl/bn.h>

#define _XOPEN_SOURCE_EXTENDED  1 /* Or gethostname won't be declared properly
                     on Compaq platforms (at least with DEC C).
                     Do not try to put it earlier, or IPv6 includes
                     get screwed...
                  */
#include OPENSSL_UNISTD

#include <iostream>

#include <udt.h>

#include "tls_common.h"

using std::cerr;
using std::endl;

int udt_client_conn(UDTSOCKET *recver, char *server_host, char *server_port);

int main(int argc, char *argv[])
{
    int ret = 1;

    SSL_CTX *s_ctx = NULL;
    SSL *s_ssl;

    int udt_sendbuff;
    int udp_sendbuff;
    int mss;
    int blast_rate;


    if (6 != argc) {
        fprintf(stderr, "Usage: tls_client server_ip server_port udt_sendbuf udp_sendbuf mss\n");
        return 1;
    }

    if (!ctx_init(&s_ctx))
        goto end;

    verify_paths(s_ctx);

    s_ssl=SSL_new(s_ctx);

    UDTSOCKET recver;

    if (!udt_client_conn(&recver, argv[1], argv[2]))
        goto end;

    udt_sendbuff = atoi(argv[3]);
    udp_sendbuff = atoi(argv[4]);
    mss = atoi(argv[5]);

    UDT::setsockopt(recver, 0, UDT_MSS, &mss, sizeof(int));
    UDT::setsockopt(recver, 0, UDT_SNDBUF, &udt_sendbuff, sizeof(int));
    UDT::setsockopt(recver, 0, UDP_SNDBUF, &udp_sendbuff, sizeof(int));
    UDT::setsockopt(recver, 0, UDT_RCVBUF, &udt_sendbuff, sizeof(int));
    UDT::setsockopt(recver, 0, UDP_RCVBUF, &udp_sendbuff, sizeof(int));

    ret = doit_biopair(s_ssl, recver, 0, fileno(stdin), fileno(stdout));

end:
    if (s_ctx != NULL) SSL_CTX_free(s_ctx);

#ifndef OPENSSL_NO_ENGINE
    ENGINE_cleanup();
#endif

    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
    ERR_remove_thread_state(NULL);
    EVP_cleanup();
    CRYPTO_mem_leaks(bio_err);
    if (bio_err != NULL) BIO_free(bio_err);

    if (recver)
        UDT::close(recver);
    UDT::cleanup();

    EXIT(ret);
    return ret;
}

int udt_client_conn(UDTSOCKET *recver, char *server_host, char *server_port)
{
    UDT::startup();

    struct addrinfo hints, *local, *peer;

    memset(&hints, 0, sizeof(struct addrinfo));

    hints.ai_flags = AI_PASSIVE;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (0 != getaddrinfo(NULL, "9000", &hints, &local))
    {
        cerr << "incorrect network address.\n" << endl;
        return 0;
    }

    *recver = UDT::socket(local->ai_family, local->ai_socktype, local->ai_protocol);

    freeaddrinfo(local);

    if (0 != getaddrinfo(server_host, server_port, &hints, &peer))
    {
        cerr << "incorrect server/peer address. " << server_host << ":" << server_port << endl;
        return 0;
    }

    // connect to the server, implict bind
    if (UDT::ERROR == UDT::connect(*recver, peer->ai_addr, peer->ai_addrlen))
    {
        cerr << "connect: " << UDT::getlasterror().getErrorMessage() << endl;
        return 0;
    }

    UDT::setsockopt(*recver, 0, UDT_RCVSYN, new bool(false), sizeof(bool));

    freeaddrinfo(peer);

    return 1;
}
