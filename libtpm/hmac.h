/*
 * libtpm: hmac.h
 *
 * Copyright (C) 2004 IBM Corporation
 * Author: J. Kravitz
 *
 *      This program is free software; you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License as published by
 *      the Free Software Foundation; either version 2 of the License, or
 *      (at your option) any later version.
 */

#ifndef HMAC_H
#define HMAC_H

uint32_t TSS_authhmac(unsigned char *digest, unsigned char *key,
		      unsigned int keylen, unsigned char *h1,
		      unsigned char *h2, unsigned char h3, ...);
uint32_t TSS_checkhmac1(unsigned char *buffer, uint32_t command,
			unsigned char *ononce, unsigned char *key,
			unsigned int keylen, ...);
uint32_t TSS_checkhmac2(unsigned char *buffer, uint32_t command,
			unsigned char *ononce, unsigned char *key1,
			unsigned int keylen1, unsigned char *key2,
			unsigned int keylen2, ...);
uint32_t TSS_rawhmac(unsigned char *digest, unsigned char *key,
		     unsigned int keylen, ...);

#endif
