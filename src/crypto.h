/*****************************************************************************
Copyright 2012 Laboratory for Advanced Computing at the University of Chicago

This file is part of UDR.

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
#ifndef CRYPTO_H
#define CRYPTO_H

#define PASSPHRASE_SIZE 32
#define HEX_PASSPHRASE_SIZE 64
#define EVP_ENCRYPT 1
#define EVP_DECRYPT 0

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
//#include <openssl/blowfish.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <limits.h>
#include <iostream>

using namespace std;

class crypto
{
private:
  //BF_KEY key;
  unsigned char ivec[ 1024 ];
  int direction;
  //int num;

    // EVP stuff
    EVP_CIPHER_CTX ctx;


char *getPassphrase(char *filename)
{
  char *pp = new char[ HEX_PASSPHRASE_SIZE ];
  FILE *in = fopen( filename , "r" );
  if ( in == NULL )
    {
      //should do something here
    }
  fgets( pp , HEX_PASSPHRASE_SIZE , in );
  return pp;
}

void free_key( char *key )
{
  memset( key , 0 , HEX_PASSPHRASE_SIZE );
  delete [] key;
}

public:

 crypto( int direc, int len, unsigned char* password)
  {
    //BF_set_key( &key , len , (unsigned char *) password );
    //free_key( password ); can't free here because is reused by threads

    memset( ivec , 0 , 1024 );
    //num = 0;
    direction = direc;
        // EVP stuff
        EVP_CIPHER_CTX_init(&ctx);
        //EVP_CipherInit_ex(&ctx, EVP_bf_cfb64(), NULL, NULL, NULL, direc);
        if (!EVP_CipherInit_ex(&ctx, EVP_bf_cfb64(), NULL, NULL, NULL, direc)) {
            fprintf(stderr, "error setting encryption scheme\n");
            exit(EXIT_FAILURE);
        }
        if (!EVP_CIPHER_CTX_set_padding(&ctx, 0)){
            fprintf(stderr, "error setting padding\n");
            exit(EXIT_FAILURE);
        }

        if (!EVP_CIPHER_CTX_set_key_length(&ctx, len)){
            fprintf(stderr, "error setting key length\n");
            exit(EXIT_FAILURE);
        }
        /* We finished modifying parameters so now we can set key and IV */
        if (!EVP_CipherInit_ex(&ctx, NULL, NULL, password, ivec, direc)){
            fprintf(stderr, "error setting password\n");
            exit(EXIT_FAILURE);
        }
  }

  void encrypt(char *in, char *out, int len)
  {
    //memcpy( out , in , len );

    //BF_cfb64_encrypt( (unsigned char *) in, (unsigned char *) out, len , &key , ivec , &num , direction );
    int evp_outlen;
    if(!EVP_CipherUpdate(&ctx, (unsigned char *)out, &evp_outlen, (unsigned char *)in, len))
    {
        fprintf(stderr, "encryption error\n");
        exit(EXIT_FAILURE);
    }
  }

};

#endif
