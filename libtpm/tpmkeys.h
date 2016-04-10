/********************************************************************************/
/*										*/
/*			     	TPM Key Structures				*/
/*			     Written by S. Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: tpmkeys.h 4702 2013-01-03 21:26:29Z kgoldman $		*/
/*										*/
/* (c) Copyright IBM Corporation 2006, 2010.					*/
/*										*/
/* All rights reserved.								*/
/* 										*/
/* Redistribution and use in source and binary forms, with or without		*/
/* modification, are permitted provided that the following conditions are	*/
/* met:										*/
/* 										*/
/* Redistributions of source code must retain the above copyright notice,	*/
/* this list of conditions and the following disclaimer.			*/
/* 										*/
/* Redistributions in binary form must reproduce the above copyright		*/
/* notice, this list of conditions and the following disclaimer in the		*/
/* documentation and/or other materials provided with the distribution.		*/
/* 										*/
/* Neither the names of the IBM Corporation nor the names of its		*/
/* contributors may be used to endorse or promote products derived from		*/
/* this software without specific prior written permission.			*/
/* 										*/
/* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS		*/
/* "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT		*/
/* LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR	*/
/* A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT		*/
/* HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,	*/
/* SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT		*/
/* LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,	*/
/* DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY	*/
/* THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT		*/
/* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE	*/
/* OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.		*/
/********************************************************************************/

#ifndef TPMKEYS_H
#define TPMKEYS_H
#include "tpm.h"
#include "tpm_structures.h"
#include <openssl/rsa.h>

#ifndef TPM_MAXIMUM_KEY_SIZE
#define TPM_MAXIMUM_KEY_SIZE  4096
#endif


#define TPM_SIZED_BUFFER_EMB(SIZE_OF_BUFFER,uniq,name) \
struct uniq { \
    uint32_t size; \
    BYTE buffer[SIZE_OF_BUFFER]; \
} name


typedef struct tdTPM_RSA_KEY_PARMS_EMB {
    uint32_t keyLength;
    uint32_t numPrimes;
    uint32_t exponentSize;
    BYTE   exponent[3];
} TPM_RSA_KEY_PARMS_EMB;


typedef struct tdTPM_SYMMETRIC_KEY_PARMS_EMB {
    uint32_t keyLength;
    uint32_t blockSize;
    uint32_t ivSize;
    BYTE   IV[256];
} TPM_SYMMETRIC_KEY_PARMS_EMB;

typedef struct tdTPM_KEY_PARMS_EMB {
    TPM_ALGORITHM_ID algorithmID; 	/* This SHALL be the key algorithm in use */
    TPM_ENC_SCHEME encScheme; 	/* This SHALL be the encryption scheme that the key uses to encrypt
                                   information */
    TPM_SIG_SCHEME sigScheme; 	/* This SHALL be the signature scheme that the key uses to perform
                                   digital signatures */
    union {
        TPM_RSA_KEY_PARMS_EMB       rsaKeyParms;
        TPM_SYMMETRIC_KEY_PARMS_EMB symKeyParms;
    } u;
} TPM_KEY_PARMS_EMB;


typedef struct tdTPM_STORE_PUBKEY_EMB {
    uint32_t keyLength;
    BYTE   modulus[TPM_MAXIMUM_KEY_SIZE/8];
} TPM_STORE_PUBKEY_EMB;


typedef struct tdTPM_KEY_EMB {
    TPM_STRUCT_VER ver;
    TPM_KEY_USAGE keyUsage;
    TPM_KEY_FLAGS keyFlags;
    TPM_AUTH_DATA_USAGE authDataUsage;
    TPM_KEY_PARMS_EMB algorithmParms;
    TPM_SIZED_BUFFER_EMB(256,
                         pcrInfo_TPM_KEY_EMB, pcrInfo);
    TPM_STORE_PUBKEY_EMB pubKey;
    TPM_SIZED_BUFFER_EMB(1024, encData_TPM_KEY_EMB, encData);
} TPM_KEY_EMB;


typedef struct tdTPM_KEY12_EMB { 
    TPM_STRUCTURE_TAG tag;
    uint16_t fill;
    TPM_KEY_USAGE keyUsage;
    TPM_KEY_FLAGS keyFlags;
    TPM_AUTH_DATA_USAGE authDataUsage;
    TPM_KEY_PARMS_EMB algorithmParms;
    TPM_SIZED_BUFFER_EMB(256,
                         pcrInfo_TPM_KEY12_EMB, pcrInfo);
    TPM_STORE_PUBKEY_EMB pubKey;
    TPM_SIZED_BUFFER_EMB(1024, encData_TPM_KEY12_EMB, encData);
} TPM_KEY12_EMB; 

typedef struct pubkeydata
{
   TPM_KEY_PARMS_EMB algorithmParms;
   TPM_STORE_PUBKEY_EMB pubKey;
   TPM_SIZED_BUFFER_EMB(256,
                        pcrInfo_pubkeydata, pcrInfo);
} pubkeydata;
   
typedef struct keydata
{
   union {
       TPM_STRUCT_VER      ver;
       TPM_STRUCTURE_TAG   tag;       // 1
   } v;
   TPM_KEY_USAGE       keyUsage;      // 2
   TPM_KEY_FLAGS       keyFlags;      // 3
   TPM_AUTH_DATA_USAGE authDataUsage; // 4
   pubkeydata     pub;
   TPM_SIZED_BUFFER_EMB(1024, encData_keydata, encData);
} keydata;


#endif
