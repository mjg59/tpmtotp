/*
 * libtpm: tpm.h
 *
 * Copyright (C) 2004 IBM Corporation
 * Author: J. Kravitz
 *
 *      This program is free software; you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License as published by
 *      the Free Software Foundation; either version 2 of the License, or
 *      (at your option) any later version.
 */

#ifndef TPM_H
#define TPM_H

#define ERR_MASK             0x80000000	/* mask to define error state */
#define ERR_BAD_RESP         0x80001000	/* response not formatted correctly */
#define ERR_HMAC_FAIL        0x80001001	/* HMAC authorization failed */
#define ERR_NULL_ARG         0x80001002	/* An argument was NULL */
#define ERR_BAD_ARG          0x80001003	/* An argument had an invalid value */
#define ERR_CRYPT_ERR        0x80001004	/* error in an OpenSSL library call */
#define ERR_IO               0x80001005	/* An I/O Error occured */
#define ERR_MEM_ERR          0x80001006	/* A memory allocation error occurred */

#define TPM_MAX_BUFF_SIZE              4096
#define TPM_HASH_SIZE                  20
#define TPM_NONCE_SIZE                 20

#define TPM_U16_SIZE                   2
#define TPM_U32_SIZE                   4

#define TPM_PARAMSIZE_OFFSET           TPM_U16_SIZE
#define TPM_RETURN_OFFSET              ( TPM_U16_SIZE + TPM_U32_SIZE )
#define TPM_DATA_OFFSET                ( TPM_RETURN_OFFSET + TPM_U32_SIZE )

#define STORE32(buffer,offset,value)  { *(uint32_t *)&buffer[offset] = htonl(value); }
#define STORE16(buffer,offset,value)  { *(uint16_t *)&buffer[offset] = htons(value); }
#define STORE32N(buffer,offset,value) { *(uint32_t *)&buffer[offset] = value; }
#define STORE16N(buffer,offset,value) { *(uint16_t *)&buffer[offset] = value; }
#define LOAD32(buffer,offset)         ( ntohl(*(uint32_t *)&buffer[offset]) )
#define LOAD16(buffer,offset)         ( ntohs(*(uint16_t *)&buffer[offset]) )
#define LOAD32N(buffer,offset)        ( *(uint32_t *)&buffer[offset] )
#define LOAD16N(buffer,offset)        ( *(uint16_t *)&buffer[offset] )
#define ADD32(buffer,offset,value)    { STORE32(buffer,offset,( LOAD32(buffer,offset) + value ) )  }


#endif
