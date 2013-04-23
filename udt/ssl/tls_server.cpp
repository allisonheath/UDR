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
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

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

#define TEST_SERVER_CERT "server.pem"

using std::cerr;
using std::endl;

int udt_server_conn(UDTSOCKET *recver, char port[]);

int main(int argc, char *argv[])
{
    int ret = 1;

    char server_cert[] = TEST_SERVER_CERT;
    char *server_key = NULL;

    SSL_CTX *s_ctx = NULL;
    SSL *s_ssl;

    int udt_sendbuff;
    int udp_sendbuff;
    int mss;

    if (argc != 5) {
        fprintf(stderr, "Usage: tls_server port udt_sendbuff udp_sendbuff mss\n");
        exit(1);
    }

    udt_sendbuff = atoi(argv[2]);
    udp_sendbuff = atoi(argv[3]);
    mss = atoi(argv[4]);


    if (!ctx_init(&s_ctx))
        goto end;

    if (!SSL_CTX_use_certificate_file(s_ctx, server_cert, SSL_FILETYPE_PEM)) {
        ERR_print_errors(bio_err);
    }
    else if (!SSL_CTX_use_PrivateKey_file(s_ctx,
        (server_key ? server_key : server_cert), SSL_FILETYPE_PEM)) {
        ERR_print_errors(bio_err);
        goto end;
    }

    verify_paths(s_ctx);

    {
        int session_id_context = 0;
        SSL_CTX_set_session_id_context(s_ctx,
            (const unsigned char *)(void *)&session_id_context,
            sizeof session_id_context);
    }

    s_ssl=SSL_new(s_ctx);

    UDTSOCKET recver;

    if (!udt_server_conn(&recver, argv[1]))
        goto end;

    UDT::setsockopt(recver, 0, UDT_MSS, &mss, sizeof(int));
    UDT::setsockopt(recver, 0, UDT_SNDBUF, &udt_sendbuff, sizeof(int));
    UDT::setsockopt(recver, 0, UDP_SNDBUF, &udp_sendbuff, sizeof(int));
    UDT::setsockopt(recver, 0, UDT_RCVBUF, &udt_sendbuff, sizeof(int));
    UDT::setsockopt(recver, 0, UDP_RCVBUF, &udp_sendbuff, sizeof(int));


    ret = doit_biopair(s_ssl, recver, 1, fileno(stdin), fileno(stdout));

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

int udt_server_conn(UDTSOCKET *recver, char port[])
{
    addrinfo hints;
    addrinfo* res;

    UDT::startup();

    memset(&hints, 0, sizeof(struct addrinfo));

    hints.ai_flags = AI_PASSIVE;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    //string service(port);
    if (0 != getaddrinfo(NULL, port, &hints, &res)) {
        fprintf(stderr, "illegal port number or port is busy.\n");
        return 0;
    }

    UDTSOCKET serv = UDT::socket(res->ai_family, res->ai_socktype, res->ai_protocol);

    if (UDT::ERROR == UDT::bind(serv, res->ai_addr, res->ai_addrlen)) {
        fprintf(stderr, "bind: %s", UDT::getlasterror().getErrorMessage());
        return 0;
    }

    freeaddrinfo(res);

    fprintf(stderr, "server is ready at port: %s\n", port);

    if (UDT::ERROR == UDT::listen(serv, 1))
    {
       fprintf(stderr, "listen: %s\n", UDT::getlasterror().getErrorMessage());
       return 0;
    }

    sockaddr_storage clientaddr;
    int addrlen = sizeof(clientaddr);

    if (UDT::INVALID_SOCK == (*recver = UDT::accept(serv,
        (sockaddr*)&clientaddr, &addrlen))) {
        fprintf(stderr, "accept: %s\n", UDT::getlasterror().getErrorMessage());
        return 0;
    }

    UDT::setsockopt(*recver, 0, UDT_RCVSYN, new bool(false), sizeof(bool));

    // only take one connection
    UDT::close(serv);

    return 1;
}


