/********************************************************************************/
/*										*/
/*			     	TPM TakeOwnerShip Routine			*/
/*			     Written by J. Kravitz 				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: owner.c 4702 2013-01-03 21:26:29Z kgoldman $			*/
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef TPM_POSIX
#include <netinet/in.h>
#endif
#ifdef TPM_WINDOWS
#include <winsock2.h>
#endif
#include <tpm.h>
#include <tpmfunc.h>
#include <tpmutil.h>
#include <tpmkeys.h>
#include <tpm_constants.h>
#include <oiaposap.h>
#include <hmac.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>

/****************************************************************************/
/*                                                                          */
/*  Take Ownership of the TPM                                               */
/*                                                                          */
/* The arguments are...                                                     */
/*                                                                          */
/* ownpass   is the authorization data (password) for the new owner         */
/* srkpass   is the authorization data (password) for the new root key      */
/*           if NULL, authorization required flag is turned off             */
/*           both authorization values must be 20 bytes long                */
/* key       a pointer to a keydata structure to receive the SRK public key */
/*           or NULL if this information is not required                    */
/*                                                                          */
/****************************************************************************/
uint32_t TPM_TakeOwnership(unsigned char *ownpass, 
                           unsigned char *srkpass, 
                           uint32_t keylen,
			   unsigned char *pcrInfoBuffer,
			   uint32_t pcrInfoSize,
                           keydata *key,
                           TPM_BOOL v12)
{
	/* required OAEP padding P parameter */
	unsigned char tpm_oaep_pad_str[] = { 'T', 'C', 'P', 'A' };
	uint32_t ret;
	int iret;
	STACK_TPM_BUFFER(tpmdata)                       /* request/response buffer */
	pubkeydata tpmpubkey;                           /* public endorsement key data */
	uint32_t srkparamsize;                          /* SRK parameter buffer size */
	RSA *pubkey;                                    /* PubEK converted to OpenSSL format */
	unsigned char * padded = NULL;                  /* area for OAEP padding */
	keydata srk;                                    /* key info for SRK */
	unsigned char dummypass[TPM_HASH_SIZE];         /* dummy srk password */
	unsigned char *spass;                           /* pointer to srkpass or dummy */
      
	/* data to be inserted into Take Owner Request Buffer (in Network Byte Order) */
	/* the uint32_t and uint16_t values are stored in network byte order so they
	** are in the correct format when being hashed by the HMAC calculation */
	uint32_t command;                                /* command ordinal */
	uint16_t protocol;                               /* protocol ID */
	uint32_t oencdatasize;                           /* owner auth data encrypted size */
	unsigned char * ownerencr = NULL;                /* owner auth data encrypted */
	uint32_t sencdatasize;                           /* srk auth data encrypted size */
	unsigned char * srkencr = NULL;                  /* srk auth data encrypted */
	STACK_TPM_BUFFER(srk_param_buff)
	unsigned char nonceodd[TPM_HASH_SIZE];           /* odd nonce */
	unsigned char authdata[TPM_HASH_SIZE];           /* auth data */
	session sess;
	STACK_TPM_BUFFER(response);

	/* check that parameters are valid */
	if (ownpass == NULL) 
		return ERR_NULL_ARG;
	if (srkpass == NULL) {
		memset(dummypass,0,sizeof dummypass);
		spass = dummypass;
	} else {
		spass = srkpass;
	}

	/* set up command and protocol values for TakeOwnership function */
	command =  htonl(TPM_ORD_TakeOwnership);
	protocol = htons(TPM_PID_OWNER);
	/* get the TPM Endorsement Public Key */
	ret = TPM_ReadPubek(&tpmpubkey);
	if (ret) 
		return ret;
	/* convert the public key to OpenSSL format */
	pubkey = TSS_convpubkey(&tpmpubkey);
	if (pubkey == NULL) 
		return ERR_CRYPT_ERR;
	
	padded = calloc(RSA_size(pubkey),1);
	if (NULL == padded) {
		ret = ERR_MEM_ERR;
		goto failexit;
	}
	ownerencr = calloc(RSA_size(pubkey),1);
	if (NULL == ownerencr) {
		ret = ERR_MEM_ERR;
		goto failexit;
	}
	srkencr = calloc(RSA_size(pubkey),1);
	if (NULL == srkencr) {
		ret = ERR_MEM_ERR;
		goto failexit;
	}
	
	/* Pad and then encrypt the owner data using the RSA public key */
	iret = RSA_padding_add_PKCS1_OAEP(padded,RSA_size(pubkey),
	                                  ownpass,TPM_HASH_SIZE,tpm_oaep_pad_str,sizeof tpm_oaep_pad_str);
	if (iret == 0) {
		ret = ERR_CRYPT_ERR;
		goto failexit;
	}
	iret = RSA_public_encrypt(RSA_size(pubkey),padded,ownerencr,pubkey,RSA_NO_PADDING);
	if (iret < 0) {
		ret = ERR_CRYPT_ERR;
		goto failexit;
	}
	oencdatasize = htonl(iret);
	/* Pad and then encrypt the SRK data using the RSA public key */
	iret = RSA_padding_add_PKCS1_OAEP(padded,RSA_size(pubkey),
	                                 spass,TPM_HASH_SIZE,tpm_oaep_pad_str,sizeof tpm_oaep_pad_str);
	if (iret == 0) {
		ret = ERR_CRYPT_ERR;
		goto failexit;
	}
	iret = RSA_public_encrypt(RSA_size(pubkey),padded,srkencr,pubkey,RSA_NO_PADDING);

	if (iret < 0) {
		ret = ERR_CRYPT_ERR;
		goto failexit;
	}
	sencdatasize = htonl(iret);
	RSA_free(pubkey);
	pubkey = NULL;
	if ((int)ntohl(oencdatasize) < 0) {
		ret = ERR_CRYPT_ERR;
		goto failexit;
	}
	if ((int)ntohl(sencdatasize) < 0) {
		ret = ERR_CRYPT_ERR;
		goto failexit;
	}
	/* fill the SRK-params key structure */

	/* get tpm version */

	if (v12 == FALSE) {
		ret = TPM_GetCapability(TPM_CAP_VERSION,
		                        NULL,
		                        &response);
		if (ret != 0) {
			goto failexit;
		}
		memcpy(&(srk.v.ver), response.buffer, 4);
	} else {
		srk.v.tag = TPM_TAG_KEY12;
	}
	srk.keyUsage = 0x0011;                   /* Storage Key */
	srk.keyFlags = 0;
	if (srkpass != NULL) srk.authDataUsage = 0x01;
	else                 srk.authDataUsage = 0x00;
	srk.encData.size = 0;                      /* private key not specified here */
	srk.pub.algorithmParms.algorithmID = 0x00000001;          /* RSA */
	srk.pub.algorithmParms.encScheme = 0x0003;              /* RSA OAEP SHA1 MGF1 */
	srk.pub.algorithmParms.sigScheme = 0x0001;              /* NONE */
	srk.pub.algorithmParms.u.rsaKeyParms.keyLength = keylen;
	srk.pub.algorithmParms.u.rsaKeyParms.numPrimes = 2;
	srk.pub.algorithmParms.u.rsaKeyParms.exponentSize = 0;                   /* defaults to 0x010001 */
	srk.pub.pubKey.keyLength = 0;                   /* not used here */
	srk.pub.pcrInfo.size = 0;                  /* not used here */
	srk.pub.pcrInfo.size = pcrInfoSize;
	memcpy(srk.pub.pcrInfo.buffer, pcrInfoBuffer, pcrInfoSize);
	/* convert to a memory buffer */
	srkparamsize =  TPM_WriteKey(&srk_param_buff,&srk);
	/* generate the odd nonce */
	ret = TSS_gennonce(nonceodd);
	if (ret == 0) {
		goto failexit;
	}
	/* initiate the OIAP protocol */
	ret = TSS_SessionOpen(SESSION_OIAP,  /* only OIAP ! */
	                      &sess,
	                      ownpass, TPM_ET_OWNER, 0);
	if (ret != 0) {
		goto failexit;
	}
	/* calculate the Authorization Data */
	ret = TSS_authhmac(authdata,TSS_Session_GetAuth(&sess),TPM_HASH_SIZE,TSS_Session_GetENonce(&sess),nonceodd,0,
	                   TPM_U32_SIZE,&command,
	                   TPM_U16_SIZE,&protocol,
	                   TPM_U32_SIZE,&oencdatasize,
	                   ntohl(oencdatasize),ownerencr,
	                   TPM_U32_SIZE,&sencdatasize,
	                   ntohl(sencdatasize),srkencr,
	                   srkparamsize,srk_param_buff.buffer,
	                   0,0);
	if (ret != 0) {
		TSS_SessionClose(&sess);
		goto failexit;
	}
	/* insert all the calculated fields into the request buffer */
	ret = TSS_buildbuff("00 c2 T l s @ @ % L % 00 %",&tpmdata,
	                             command,
	                               protocol,
	                                 ntohl(oencdatasize), ownerencr,
	                                   ntohl(sencdatasize), srkencr,
	                                     srkparamsize, srk_param_buff.buffer,
	                                       TSS_Session_GetHandle(&sess),
	                                         TPM_HASH_SIZE, nonceodd,
	                                              TPM_HASH_SIZE, authdata);
	if ((ret & ERR_MASK) != 0) {
		TSS_SessionClose(&sess);
		goto failexit;
	}
	/* transmit the request buffer to the TPM device and read the reply */
	ret = TPM_Transmit(&tpmdata,"Take Ownership");
	TSS_SessionClose(&sess);
	if (ret != 0) {
		goto failexit;
	}
	/* check the response HMAC */
	srkparamsize = TSS_KeySize(&tpmdata, TPM_DATA_OFFSET);
	if ((srkparamsize & ERR_MASK)) {
		return srkparamsize;
	}
	ret = TSS_checkhmac1(&tpmdata,command,nonceodd,TSS_Session_GetAuth(&sess),TPM_HASH_SIZE,
	                     srkparamsize,TPM_DATA_OFFSET,
	                     0,0);
	if (ret != 0) {
		goto failexit;
	}
	/* convert the returned key to a structure */
	if (key == NULL) {
		goto failexit;
	}
	TSS_KeyExtract(&tpmdata, TPM_DATA_OFFSET, key);

	return ret;

failexit:
	if (srkencr) free(srkencr);
	if (ownerencr) free(ownerencr);
	if (padded) free(padded);
	if (pubkey) RSA_free(pubkey);

	return ret;
}

/****************************************************************************/
/*                                                                          */
/*  Clear the TPM                                                           */
/*                                                                          */
/* The arguments are...                                                     */
/*                                                                          */
/* ownpass   is the authorization data (password) for the owner             */
/*           the authorization value must be 20 bytes long                  */
/*                                                                          */
/****************************************************************************/
uint32_t TPM_OwnerClear(unsigned char *ownpass)
   {
   uint32_t ret;
   STACK_TPM_BUFFER(tpmdata)
   
   /* fields to be inserted into Owner Clear Request Buffer */
   uint32_t command;
   unsigned char nonceodd[TPM_HASH_SIZE];
   unsigned char authdata[TPM_HASH_SIZE];
   session sess;

   /* check that parameters are valid */
   if (ownpass == NULL) return ERR_NULL_ARG;
   command = htonl(91);
   /* generate odd nonce */
   ret = TSS_gennonce(nonceodd);
   if (ret == 0) return ret;
   /* start OIAP Protocol */
   ret = TSS_SessionOpen(SESSION_DSAP|SESSION_OSAP|SESSION_OIAP,
                         &sess,
                         ownpass, TPM_ET_OWNER,0);
   if (ret != 0) return ret;
   ret = TSS_authhmac(authdata,TSS_Session_GetAuth(&sess),TPM_HASH_SIZE,TSS_Session_GetENonce(&sess),nonceodd,0,
                  TPM_U32_SIZE,&command,
                  0,0);
   if (ret != 0)
      {
      TSS_SessionClose(&sess);
      return ret;
      }
   ret = TSS_buildbuff("00 c2 T l L % 00 %",&tpmdata,
                       command,
                       TSS_Session_GetHandle(&sess),
                       TPM_HASH_SIZE,
                       nonceodd,
                       TPM_HASH_SIZE,
                       authdata);
   if ((ret & ERR_MASK) != 0)
      {
      TSS_SessionClose(&sess);
      return ret;
      }
   ret = TPM_Transmit(&tpmdata,"Owner Clear");
   TSS_SessionClose(&sess);
   return ret;
   }


uint32_t TPM_ForceClear()
{
	uint32_t ret;
	uint32_t ordinal_no = htonl(TPM_ORD_ForceClear);
	STACK_TPM_BUFFER(tpmdata)
	
	ret = TSS_buildbuff("00 c1 T l",&tpmdata,
	                             ordinal_no);
	if ((ret & ERR_MASK)) {
		return ret;
	}
	
	ret = TPM_Transmit(&tpmdata,"ForceClear");

	if (ret == 0 && tpmdata.used != 10) {
		ret = ERR_BAD_RESP;
	}
	
	return ret;
}


uint32_t TPM_DisableOwnerClear(unsigned char *ownerauth  // HMAC key
                            )
{
	STACK_TPM_BUFFER(tpmdata)
	unsigned char nonceodd[TPM_NONCE_SIZE];
	unsigned char authdata[TPM_NONCE_SIZE];
  	unsigned char c = 0;
	uint32_t ordinal_no = htonl(TPM_ORD_DisableOwnerClear);
	uint32_t ret;
	session sess;
	
	/* check input arguments */
	if (NULL == ownerauth) return ERR_NULL_ARG;

	/* generate odd nonce */
	ret  = TSS_gennonce(nonceodd);
	if (0 == ret) return ERR_CRYPT_ERR;

	/* Open OSAP Session */
	ret = TSS_SessionOpen(SESSION_DSAP|SESSION_OSAP|SESSION_OIAP,
	                      &sess,
	                      ownerauth, TPM_ET_OWNER, 0);
	if (ret != 0) return ret;

	/* move Network byte order data to variable for hmac calculation */
	ret = TSS_authhmac(authdata,TSS_Session_GetAuth(&sess),TPM_HASH_SIZE,TSS_Session_GetENonce(&sess),nonceodd,c,
	                   TPM_U32_SIZE,&ordinal_no,
	                   0,0);

	if (0 != ret) {
		TSS_SessionClose(&sess);
		return ret;
	}
	/* build the request buffer */
	ret = TSS_buildbuff("00 c2 T l L % o %", &tpmdata,
	                             ordinal_no,
	                               TSS_Session_GetHandle(&sess),
	                                 TPM_NONCE_SIZE,nonceodd,
	                                   c,
	                                     TPM_HASH_SIZE,authdata);
	if ((ret & ERR_MASK)) {
		TSS_SessionClose(&sess);
		return ret;
	}
	/* transmit the request buffer to the TPM device and read the reply */
	ret = TPM_Transmit(&tpmdata,"DisableOwnerClear");
	TSS_SessionClose(&sess);

	if (ret != 0) {
		return ret;
	}

	/* check the HMAC in the response */
		
	ret = TSS_checkhmac1(&tpmdata,ordinal_no,nonceodd,TSS_Session_GetAuth(&sess),TPM_HASH_SIZE,
	                     0,0);
	
	return ret;
}


uint32_t TPM_DisableForceClear()
{
	uint32_t ret;
	uint32_t ordinal_no = htonl(TPM_ORD_DisableForceClear);
	STACK_TPM_BUFFER(tpmdata)
	
	ret = TSS_buildbuff("00 c1 T l",&tpmdata,
	                             ordinal_no);
	if ((ret & ERR_MASK)) {
		return ret;
	}
	
	ret = TPM_Transmit(&tpmdata,"DisableForceClear");

	if (ret == 0 && tpmdata.used != 10) {
		ret = ERR_BAD_RESP;
	}
	
	return ret;
}

uint32_t TSC_PhysicalPresence(uint16_t ppresence)
{
	uint32_t ret;
	uint32_t ordinal_no = htonl(TSC_ORD_PhysicalPresence);
	STACK_TPM_BUFFER(tpmdata)
	uint16_t ppresence_no = htons(ppresence);
	
	ret = TSS_buildbuff("00 c1 T l s",&tpmdata,
	                             ordinal_no,
	                               ppresence_no);
	if ((ret & ERR_MASK)) {
		return ret;
	}
	
	ret = TPM_Transmit(&tpmdata,"PhysicalPresence");
	
	if (ret == 0 && tpmdata.used != 10) {
		ret = ERR_BAD_RESP;
	}

	return ret;
}

uint32_t TPM_ResetEstablishmentBit()
{
	uint32_t ret;
	uint32_t ordinal_no = htonl(TSC_ORD_ResetEstablishmentBit);
	STACK_TPM_BUFFER(tpmdata)
	
	ret = TSS_buildbuff("00 c1 T l",&tpmdata,
	                             ordinal_no);
	if ((ret & ERR_MASK)) {
		return ret;
	}
	
	ret = TPM_Transmit(&tpmdata,"ResetEstablishmentBit");

	if (ret == 0 && tpmdata.used != 10) {
		ret = ERR_BAD_RESP;
	}
	
	return ret;
}
