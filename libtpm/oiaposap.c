/*
 * libtpm: OAIP/OSAP routines
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
#include <oiaposap.h>


/****************************************************************************/
/*                                                                          */
/* Open an OIAP session                                                     */
/*                                                                          */
/****************************************************************************/
uint32_t TSS_OIAPopen(uint32_t * handle, char *enonce)
{
	unsigned char oiap_open_fmt[] = "00 C1 T 00 00 00 0A";
	unsigned char tpmdata[TPM_MAX_BUFF_SIZE];
	uint32_t ret;
	uint32_t size;

	/* check input arguments */
	if (handle == NULL || enonce == NULL)
		return ERR_NULL_ARG;
	/* build request buffer */
	ret = TSS_buildbuff(oiap_open_fmt, tpmdata);
	if ((ret & ERR_MASK) != 0)
		return ret;
	/* transmit request to TPM and get result */
	ret = TPM_Transmit(tpmdata, "OIAP");
	if (ret != 0)
		return ret;
	size = TSS_getsize(tpmdata);
	*handle = LOAD32N(tpmdata, TPM_DATA_OFFSET);
	memcpy(enonce, &tpmdata[TPM_DATA_OFFSET + TPM_U32_SIZE],
	       TPM_NONCE_SIZE);
	return 0;
}

/****************************************************************************/
/*                                                                          */
/* Close an OIAP session                                                    */
/*                                                                          */
/****************************************************************************/
uint32_t TSS_OIAPclose(uint32_t handle)
{
	return TSS_HANDclose(handle);
}

/****************************************************************************/
/*                                                                          */
/* Open an OSAP session                                                     */
/*                                                                          */
/****************************************************************************/
uint32_t TSS_OSAPopen(osapsess *sess, unsigned char *key, uint16_t etype,
		      uint32_t evalue)
{
	unsigned char osap_open_fmt[] = "00 C1 T 00 00 00 0B S L %";
	unsigned char tpmdata[TPM_MAX_BUFF_SIZE];
	uint32_t ret;


	/* check input arguments */
	if (key == NULL || sess == NULL)
		return ERR_NULL_ARG;
	TSS_gennonce(sess->ononceOSAP);
	ret =
	    TSS_buildbuff(osap_open_fmt, tpmdata, etype, evalue,
			  TPM_NONCE_SIZE, sess->ononceOSAP);
	if ((ret & ERR_MASK) != 0)
		return ret;
	ret = TPM_Transmit(tpmdata, "OSAP");
	if (ret != 0)
		return ret;
	sess->handle = LOAD32N(tpmdata, TPM_DATA_OFFSET);
	memcpy(sess->enonce, &(tpmdata[TPM_DATA_OFFSET + TPM_U32_SIZE]),
	       TPM_NONCE_SIZE);
	memcpy(sess->enonceOSAP,
	       &(tpmdata[TPM_DATA_OFFSET + TPM_U32_SIZE + TPM_NONCE_SIZE]),
	       TPM_NONCE_SIZE);
	ret =
	    TSS_rawhmac(sess->ssecret, key, TPM_HASH_SIZE, TPM_NONCE_SIZE,
			sess->enonceOSAP, TPM_NONCE_SIZE, sess->ononceOSAP,
			0, 0);
	if (ret != 0)
		return ret;
	return 0;
}

/****************************************************************************/
/*                                                                          */
/* Close an OSAP session                                                    */
/*                                                                          */
/****************************************************************************/
uint32_t TSS_OSAPclose(osapsess * sess)
{
	uint32_t ret;

	if (sess == NULL)
		return ERR_NULL_ARG;
	ret = TSS_HANDclose(sess->handle);
	return ret;
}

/****************************************************************************/
/*                                                                          */
/* Terminate the Handle Opened by TPM_OIAPOpen, or TPM_OSAPOpen             */
/*                                                                          */
/****************************************************************************/
uint32_t TSS_HANDclose(uint32_t handle)
{
	unsigned char hand_close_fmt[] = "00 C1 T 00 00 00 96 l";
	unsigned char tpmdata[TPM_MAX_BUFF_SIZE];
	uint32_t ret;

	ret = TSS_buildbuff(hand_close_fmt, tpmdata, handle);
	if ((ret & ERR_MASK) != 0)
		return ret;
	ret = TPM_Transmit(tpmdata, "Terminate Handle");
	if (ret != 0)
		return ret;
	return 0;
}
