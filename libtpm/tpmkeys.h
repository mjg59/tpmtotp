/*
 * libtpm: tpmkeys.h
 *
 * Copyright (C) 2004 IBM Corporation
 * Author: J. Kravitz
 *
 *      This program is free software; you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License as published by
 *      the Free Software Foundation; either version 2 of the License, or
 *      (at your option) any later version.
 */

#ifndef TPMKEYS_H
#define TPMKEYS_H
#include <tpm.h>
#include <openssl/rsa.h>

typedef struct pubkeydata {
	uint32_t algorithm;
	uint16_t encscheme;
	uint16_t sigscheme;
	uint32_t keybitlen;
	uint32_t numprimes;
	uint32_t expsize;
	unsigned char exponent[3];
	uint32_t keylength;
	unsigned char modulus[256];
	uint32_t pcrinfolen;
	unsigned char pcrinfo[256];
} pubkeydata;

typedef struct keydata {
	unsigned char version[4];
	uint16_t keyusage;
	uint32_t keyflags;
	unsigned char authdatausage;
	pubkeydata pub;
	uint32_t privkeylen;
	unsigned char encprivkey[1024];
} keydata;


int TSS_KeyExtract(unsigned char *keybuff, keydata * k);
int TSS_PubKeyExtract(unsigned char *pkeybuff, pubkeydata * k,
		      int pcrpresent);
RSA *TSS_convpubkey(pubkeydata * k);
uint32_t TPM_BuildKey(unsigned char *buffer, keydata * k);
int TSS_KeySize(unsigned char *keybuff);
int TSS_PubKeySize(unsigned char *keybuff, int pcrpresent);
void TSS_Key2Pub(unsigned char *keybuff, unsigned char *pkey,
		 unsigned int *plen);
void TSS_pkeyprint(pubkeydata * key, unsigned char *fprint);
void TSS_keyprint(unsigned char *keybuff, unsigned char *fprint);
uint32_t TSS_lkeyprint(uint32_t keyhandle, unsigned char *keyauth,
		       unsigned char *fprint);
#endif
