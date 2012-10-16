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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/blowfish.h>
#include <openssl/rand.h>
#include <limits.h>
#include <iostream>

using namespace std;

class crypto
{
private:
  BF_KEY key;
  unsigned char ivec[ 1024 ];
  int direction;
  int num;

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
    BF_set_key( &key , len , (unsigned char *) password );
    //free_key( password ); can't free here because is reused by threads

    memset( ivec , 0 , 1024 );
    num = 0;
    direction = direc;
  }
  
  void encrypt( char *in , char *out , int len )
  {
    //memcpy( out , in , len );
    BF_cfb64_encrypt( (unsigned char *) in, (unsigned char *) out, len , &key , ivec , &num , direction );
  }
  
};

#endif