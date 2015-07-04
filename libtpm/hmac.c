/*
 * libtpm: HMAC routines
 *
 * Copyright (C) 2004 IBM Corporation
 * Author: J. Kravitz
 *
 *      This program is free software; you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License as published by
 *      the Free Software Foundation; either version 2 of the License, or
 *      (at your option) any later version.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <tpm.h>
#include <tpmutil.h>
#include <hmac.h>

#include <openssl/sha.h>
#include <openssl/hmac.h>

#define TPM_TAG_RSP_COMMAND       0x00C4
#define TPM_TAG_RSP_AUTH1_COMMAND 0x00C5
#define TPM_TAG_RSP_AUTH2_COMMAND 0x00C6

/****************************************************************************/
/*                                                                          */
/* Validate the HMAC in an AUTH1 response                                   */
/*                                                                          */
/* This function validates the Authorization Digest for all AUTH1           */
/* responses.                                                               */
/*                                                                          */
/* The arguments are...                                                     */
/*                                                                          */
/* buffer - a pointer to response buffer                                    */
/* command - the command code from the original request                     */
/* ononce - a pointer to a 20 byte array containing the oddNonce            */
/* key    - a pointer to the key used in the request HMAC                   */
/* keylen - the size of the key                                             */
/* followed by a variable length set of arguments, which must come in       */
/* pairs.                                                                   */
/* The first value in each pair is the length of the data in the second     */
/*   argument of the pair                                                   */
/* The second value in each pair is an offset in the buffer to the data     */
/*   to be included in the hash for the paramdigest                         */
/* There should NOT be pairs for the TPM_RESULT or TPM_COMMAND_CODE         */
/* The last pair must be followed by a pair containing 0,0                  */
/*                                                                          */
/****************************************************************************/
uint32_t TSS_checkhmac1(unsigned char *buffer, uint32_t command,
			unsigned char *ononce, unsigned char *key,
			unsigned int keylen, ...)
{
	uint32_t bufsize;
	uint16_t tag;
	uint32_t ordinal;
	uint32_t result;
	unsigned char *enonce;
	unsigned char *continueflag;
	unsigned char *authdata;
	unsigned char testhmac[20];
	unsigned char paramdigest[20];
	SHA_CTX sha;
	unsigned int dlen;
	unsigned int dpos;
	va_list argp;

	bufsize = LOAD32(buffer, TPM_U16_SIZE);
	tag = LOAD16(buffer, 0);
	ordinal = command;
	result = LOAD32N(buffer, TPM_RETURN_OFFSET);

	if (tag == TPM_TAG_RSP_COMMAND)
		return 0;
	if (tag != TPM_TAG_RSP_AUTH1_COMMAND)
		return ERR_HMAC_FAIL;
	authdata = buffer + bufsize - TPM_HASH_SIZE;
	continueflag = authdata - 1;
	enonce = continueflag - TPM_NONCE_SIZE;
	SHA1_Init(&sha);
	SHA1_Update(&sha, &result, 4);
	SHA1_Update(&sha, &ordinal, 4);
	va_start(argp, keylen);
	for (;;) {
		dlen = (unsigned int) va_arg(argp, unsigned int);
		if (dlen == 0)
			break;
		dpos = (unsigned int) va_arg(argp, unsigned int);
		SHA1_Update(&sha, buffer + dpos, dlen);
	}
	va_end(argp);
	SHA1_Final(paramdigest, &sha);
	TSS_rawhmac(testhmac, key, keylen, TPM_HASH_SIZE, paramdigest,
		    TPM_NONCE_SIZE, enonce,
		    TPM_NONCE_SIZE, ononce, 1, continueflag, 0, 0);
	if (memcmp(testhmac, authdata, TPM_HASH_SIZE) != 0)
		return ERR_HMAC_FAIL;
	return 0;
}

/****************************************************************************/
/*                                                                          */
/* Validate the HMACS in an AUTH2 response                                  */
/*                                                                          */
/* This function validates the Authorization Digests for all AUTH2          */
/* responses.                                                               */
/*                                                                          */
/* The arguments are...                                                     */
/*                                                                          */
/* buffer - a pointer to response buffer                                    */
/* command - the command code from the original request                     */
/* ononce - a pointer to a 20 byte array containing the oddNonce            */
/* key1    - a pointer to the 1st   key used in the request HMAC            */
/* keylen1 - the size of the key                                            */
/* key2    - a pointer to the 2nd   key used in the request HMAC            */
/* keylen2 - the size of the key                                            */
/* followed by a variable length set of arguments, which must come in       */
/* pairs.                                                                   */
/* The first value in each pair is the length of the data in the second     */
/*   argument of the pair                                                   */
/* The second value in each pair is an offset in the buffer to the data     */
/*   to be included in the hash for the paramdigest                         */
/* There should NOT be pairs for the TPM_RESULT or TPM_COMMAND_CODE         */
/* The last pair must be followed by a pair containing 0,0                  */
/*                                                                          */
/****************************************************************************/
uint32_t TSS_checkhmac2(unsigned char *buffer, uint32_t command,
			unsigned char *ononce, unsigned char *key1,
			unsigned int keylen1, unsigned char *key2,
			unsigned int keylen2, ...)
{
	uint32_t bufsize;
	uint16_t tag;
	uint32_t ordinal;
	uint32_t result;
	unsigned char *enonce1;
	unsigned char *continueflag1;
	unsigned char *authdata1;
	unsigned char *enonce2;
	unsigned char *continueflag2;
	unsigned char *authdata2;
	unsigned char testhmac1[20];
	unsigned char paramdigest[20];
	unsigned char testhmac2[20];
	SHA_CTX sha;
	unsigned int dlen;
	unsigned int dpos;
	va_list argp;

	bufsize = LOAD32(buffer, TPM_U16_SIZE);
	tag = LOAD16(buffer, 0);
	ordinal = command;
	result = LOAD32N(buffer, TPM_RETURN_OFFSET);

	if (tag == TPM_TAG_RSP_COMMAND)
		return 0;
	if (tag != TPM_TAG_RSP_AUTH2_COMMAND)
		return ERR_HMAC_FAIL;
	authdata1 =
	    buffer + bufsize - (TPM_HASH_SIZE + 1 + TPM_HASH_SIZE +
				TPM_HASH_SIZE);
	authdata2 = buffer + bufsize - (TPM_HASH_SIZE);
	continueflag1 = authdata1 - 1;
	continueflag2 = authdata2 - 1;
	enonce1 = continueflag1 - TPM_NONCE_SIZE;
	enonce2 = continueflag2 - TPM_NONCE_SIZE;
	SHA1_Init(&sha);
	SHA1_Update(&sha, &result, 4);
	SHA1_Update(&sha, &ordinal, 4);
	va_start(argp, keylen2);
	for (;;) {
		dlen = (unsigned int) va_arg(argp, unsigned int);
		if (dlen == 0)
			break;
		dpos = (unsigned int) va_arg(argp, unsigned int);
		SHA1_Update(&sha, buffer + dpos, dlen);
	}
	SHA1_Final(paramdigest, &sha);
	TSS_rawhmac(testhmac1, key1, keylen1, TPM_HASH_SIZE, paramdigest,
		    TPM_NONCE_SIZE, enonce1,
		    TPM_NONCE_SIZE, ononce, 1, continueflag1, 0, 0);
	TSS_rawhmac(testhmac2, key2, keylen2, TPM_HASH_SIZE, paramdigest,
		    TPM_NONCE_SIZE, enonce2,
		    TPM_NONCE_SIZE, ononce, 1, continueflag2, 0, 0);
	if (memcmp(testhmac1, authdata1, TPM_HASH_SIZE) != 0)
		return ERR_HMAC_FAIL;
	if (memcmp(testhmac2, authdata2, TPM_HASH_SIZE) != 0)
		return ERR_HMAC_FAIL;
	return 0;
}

/****************************************************************************/
/*                                                                          */
/* Calculate HMAC value for an AUTH1 command                                */
/*                                                                          */
/* This function calculates the Authorization Digest for all OIAP           */
/* commands.                                                                */
/*                                                                          */
/* The arguments are...                                                     */
/*                                                                          */
/* digest - a pointer to a 20 byte array that will receive the result       */
/* key    - a pointer to the key to be used in the HMAC calculation         */
/* keylen - the size of the key in bytes                                    */
/* h1     - a pointer to a 20 byte array containing the evenNonce           */
/* h2     - a pointer to a 20 byte array containing the oddNonce            */
/* h3     - an unsigned character containing the continueAuthSession value  */
/* followed by a variable length set of arguments, which must come in       */
/* pairs.                                                                   */
/* The first value in each pair is the length of the data in the second     */
/*   argument of the pair                                                   */
/* The second value in each pair is a pointer to the data to be hashed      */
/*   into the paramdigest.                                                  */
/* The last pair must be followed by a pair containing 0,0                  */
/*                                                                          */
/****************************************************************************/
uint32_t TSS_authhmac(unsigned char *digest, unsigned char *key,
		      unsigned int keylen, unsigned char *h1,
		      unsigned char *h2, unsigned char h3, ...)
{
	unsigned char paramdigest[TPM_HASH_SIZE];
	SHA_CTX sha;
	unsigned int dlen;
	unsigned char *data;
	unsigned char c;

	va_list argp;

	SHA1_Init(&sha);
	if (h1 == NULL || h2 == NULL)
		return ERR_NULL_ARG;
	c = h3;
	va_start(argp, h3);
	for (;;) {
		dlen = (unsigned int) va_arg(argp, unsigned int);
		if (dlen == 0)
			break;
		data = (unsigned char *) va_arg(argp, int *);
		if (data == NULL)
			return ERR_NULL_ARG;
		SHA1_Update(&sha, data, dlen);
	}
	va_end(argp);
	SHA1_Final(paramdigest, &sha);
	TSS_rawhmac(digest, key, keylen, TPM_HASH_SIZE, paramdigest,
		    TPM_NONCE_SIZE, h1, TPM_NONCE_SIZE, h2, 1, &c, 0, 0);
	return 0;
}

/****************************************************************************/
/*                                                                          */
/* Calculate Raw HMAC value                                                 */
/*                                                                          */
/* This function calculates an HMAC digest                                  */
/*                                                                          */
/* The arguments are...                                                     */
/*                                                                          */
/* digest - a pointer to a 20 byte array that will receive the result       */
/* key    - a pointer to the key to be used in the HMAC calculation         */
/* keylen - the size of the key in bytes                                    */
/* followed by a variable length set of arguments, which must come in       */
/* pairs.                                                                   */
/* The first value in each pair is the length of the data in the second     */
/*   argument of the pair                                                   */
/* The second value in each pair is a pointer to the data to be hashed      */
/*   into the paramdigest.                                                  */
/* The last pair must be followed by a pair containing 0,0                  */
/*                                                                          */
/****************************************************************************/
uint32_t TSS_rawhmac(unsigned char *digest, unsigned char *key,
		     unsigned int keylen, ...)
{
	HMAC_CTX hmac;
	unsigned int dlen;
	unsigned char *data;
	va_list argp;

#ifdef HAVE_HMAC_CTX_CLEANUP
	HMAC_CTX_init(&hmac);
#endif
	HMAC_Init(&hmac, key, keylen, EVP_sha1());
	va_start(argp, keylen);
	for (;;) {
		dlen = (unsigned int) va_arg(argp, unsigned int);
		if (dlen == 0)
			break;
		data = (unsigned char *) va_arg(argp, int *);
		if (data == NULL)
			return ERR_NULL_ARG;
		HMAC_Update(&hmac, data, dlen);
	}
	HMAC_Final(&hmac, digest, &dlen);
#ifdef HAVE_HMAC_CTX_CLEANUP
	HMAC_CTX_cleanup(&hmac);
#else
	HMAC_cleanup(&hmac);
#endif
	va_end(argp);
	return 0;
}
