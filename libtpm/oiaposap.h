/*
 * libtpm: oiaposap.h 
 *
 * Copyright (C) 2004 IBM Corporation
 * Author: J. Kravitz
 *
 *      This program is free software; you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License as published by
 *      the Free Software Foundation; either version 2 of the License, or
 *      (at your option) any later version.
 */

#ifndef OIAPOSAP_H
#define OIAPOSAP_H
#include <tpm.h>

typedef struct osapsess {
	uint32_t handle;
	unsigned char enonce[TPM_NONCE_SIZE];
	unsigned char enonceOSAP[TPM_NONCE_SIZE];
	unsigned char ononceOSAP[TPM_NONCE_SIZE];
	unsigned char ssecret[TPM_HASH_SIZE];
	unsigned char ononce[TPM_NONCE_SIZE];
} osapsess;

uint32_t TSS_HANDclose(uint32_t handle);
uint32_t TSS_OIAPopen(uint32_t * handle, char *enonce);
uint32_t TSS_OIAPclose(uint32_t handle);
uint32_t TSS_OSAPopen(osapsess * sess, unsigned char *key, uint16_t etype,
		      uint32_t evalue);
uint32_t TSS_OSAPclose(osapsess * sess);

#endif
