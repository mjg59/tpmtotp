/*
 * libtpm: tpmfunc.h
 *
 * Copyright (C) 2004 IBM Corporation
 * Author: J. Kravitz
 *
 *      This program is free software; you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License as published by
 *      the Free Software Foundation; either version 2 of the License, or
 *      (at your option) any later version.
 */

#ifndef TPMFUNC_H
#define TPMFUNC_H

#include <stdint.h>
#include <tpmkeys.h>
#include <tpmutil.h>

/* Basic TPM_ commands */
uint32_t TPM_ReadPubek(pubkeydata * k);
uint32_t TPM_DisableReadPubek(unsigned char *ownauth);
uint32_t TPM_OwnerReadPubek(unsigned char *ownauth, pubkeydata * k);
uint32_t TPM_TakeOwnership(unsigned char *ownpass, unsigned char *srkpass,
			   keydata * key);
uint32_t TPM_OwnerClear(unsigned char *ownpass);
uint32_t TPM_CreateWrapKey(uint32_t keyhandle,
			   unsigned char *keyauth, unsigned char *newauth,
			   unsigned char *migauth,
			   keydata * keyparms, keydata * key,
			   unsigned char *keyblob, unsigned int *bloblen);
uint32_t TPM_LoadKey(uint32_t keyhandle, unsigned char *keyauth,
		     keydata * keyparms, uint32_t * newhandle);
uint32_t TPM_ChangeAuth(uint32_t keyhandle,
			unsigned char *parauth,
			unsigned char *keyauth,
			unsigned char *newauth, keydata * key);
uint32_t TPM_ChangeSRKAuth(unsigned char *ownauth, unsigned char *newauth);
uint32_t TPM_ChangeOwnAuth(unsigned char *ownauth, unsigned char *newauth);
uint32_t TPM_GetPubKey(uint32_t keyhandle,
		       unsigned char *keyauth,
		       unsigned char *keyblob, unsigned int *keyblen);
uint32_t TPM_EvictKey(uint32_t keyhandle);
uint32_t TPM_Sign(uint32_t keyhandle, unsigned char *keyauth,
		  unsigned char *data, int datalen,
		  unsigned char *sig, unsigned int *siglen);
uint32_t TPM_Quote(uint32_t keyhandle,
		   uint32_t pcrmap,
		   unsigned char *keyauth,
		   unsigned char *data,
		   unsigned char *pcrvalues,
		   unsigned char *blob, unsigned int *bloblen);
uint32_t TPM_Seal(uint32_t keyhandle,
		  unsigned char *pcrinfo, uint32_t pcrinfosize,
		  unsigned char *keyauth,
		  unsigned char *dataauth,
		  unsigned char *data, unsigned int datalen,
		  unsigned char *blob, unsigned int *bloblen);
uint32_t TPM_Unseal(uint32_t keyhandle,
		    unsigned char *keyauth,
		    unsigned char *dataauth,
		    unsigned char *blob, unsigned int bloblen,
		    unsigned char *rawdata, unsigned int *datalen);
uint32_t TPM_UnBind(uint32_t keyhandle,
		    unsigned char *keyauth,
		    unsigned char *data, unsigned int datalen,
		    unsigned char *blob, unsigned int *bloblen);
uint32_t TSS_Bind(RSA * key,
		  unsigned char *data, unsigned int datalen,
		  unsigned char *blob, unsigned int *bloblen);
uint32_t TPM_GetCapabilityOwner(unsigned char *ownerdata, uint32_t osize,
				uint32_t * volflags, uint32_t * nvolflags);
uint32_t TPM_GetCapability(uint32_t caparea, unsigned char *subcap,
			   int subcaplen, unsigned char *resp,
			   unsigned int *resplen);
uint32_t TPM_PcrRead(uint32_t pcrindex, unsigned char *pcrvalue);
uint32_t TPM_Extend(uint32_t pcrindex, unsigned char *pcrvalue);
uint32_t TPM_AuthorizeMigrationKey(unsigned char *ownpass,
				   int migtype,
				   unsigned char *keyblob,
				   unsigned int keyblen,
				   unsigned char *migblob,
				   unsigned int *migblen);
uint32_t TPM_CreateMigrationBlob(unsigned int keyhandle,
				 unsigned char *keyauth,
				 unsigned char *migauth,
				 int migtype,
				 unsigned char *migblob,
				 unsigned int migblen,
				 unsigned char *keyblob,
				 unsigned int keyblen,
				 unsigned char *rndblob,
				 unsigned int *rndblen,
				 unsigned char *outblob,
				 unsigned int *outblen);
uint32_t TPM_ConvertMigrationBlob(unsigned int keyhandle,
				  unsigned char *keyauth,
				  unsigned char *rndblob,
				  unsigned int rndblen,
				  unsigned char *keyblob,
				  unsigned int keyblen,
				  unsigned char *encblob,
				  unsigned int *encblen);
uint32_t TPM_Reset();
uint32_t TPM_GetRandom(unsigned char *buf);

/* TPM helper functions */
uint32_t TPM_SealCurrPCR(uint32_t keyhandle,
			 uint32_t pcrmap,
			 unsigned char *keyauth,
			 unsigned char *dataauth,
			 unsigned char *data, unsigned int datalen,
			 unsigned char *blob, unsigned int *bloblen);
uint32_t TSS_GenPCRInfo(uint32_t pcrmap, unsigned char *pcrinfo,
			unsigned int *len);
unsigned char *TPM_GetErrMsg(uint32_t code);
#endif
