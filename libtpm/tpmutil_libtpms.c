/********************************************************************************/
/*										*/
/*			  TPM LibTPMS Interface Functions			*/
/*			     Written by S. Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: tpmutil_libtpms.c 4702 2013-01-03 21:26:29Z kgoldman $		*/
/*										*/
/*			       IBM Confidential					*/
/*			     OCO Source Materials				*/
/*			 (c) Copyright IBM Corp. 2010				*/
/*			      All Rights Reserved			        */
/*										*/
/*	   The source code for this program is not published or otherwise	*/
/*	   divested of its trade secrets, irrespective of what has been		*/
/*	   deposited with the U.S. Copyright Office.				*/
/*										*/
/********************************************************************************/

#ifdef TPM_USE_LIBTPMS

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "tpm_types.h"
#include "tpm_error.h"

#ifdef USE_IN_TREE_LIBTPMS

#include "../../../src/tpm_library.h"

#else

#include <libtpms/tpm_library.h>

#endif

#include "tpmutil.h"
#include "tpm_lowlevel.h"


static uint32_t TPM_OpenLibTPMS(int *sockfd);
static uint32_t TPM_CloseLibTPMS(int sockfd);
static uint32_t TPM_SendLibTPMS(int sockfd, struct tpm_buffer *tb,
                                const char *msg);
static uint32_t TPM_ReceiveLibTPMS(int sockfd, struct tpm_buffer *tb);

static struct tpm_transport libtpms_transport = {
    .open = TPM_OpenLibTPMS,
    .close = TPM_CloseLibTPMS,
    .send = TPM_SendLibTPMS,
    .recv  = TPM_ReceiveLibTPMS,
};

void TPM_LowLevel_TransportLibTPMS_Set(void)
{
    TPM_LowLevel_Transport_Set(&libtpms_transport);
}


/*
 * Functions that implement the transport
 */
static uint32_t TPM_OpenLibTPMS(int *sockfd)
{
	(void)sockfd;
	return 0;
}

static uint32_t TPM_CloseLibTPMS(int sockfd)
{
	(void)sockfd;
	return 0;
}


static uint32_t TPM_SendLibTPMS(int sockfd, struct tpm_buffer *tb,
                                const char *msg) 
{
	unsigned char *respbuffer = NULL;
	uint32_t resp_size;
	uint32_t respbufsize;
	uint32_t rc;
	char mymsg[1024];

	(void)sockfd;

	snprintf(mymsg, sizeof(mymsg), "TPM_SendLibTPMS: To TPM [%s]",
	         msg);

	showBuff(tb->buffer, mymsg);

	rc = TPMLIB_Process(&respbuffer, &resp_size, &respbufsize,
	                    tb->buffer, tb->used);

        if (rc != TPM_SUCCESS)
                return ERR_IO;

        if (tb->size < resp_size)
                return ERR_BUFFER;

        memcpy(tb->buffer, respbuffer, resp_size);
        tb->used = resp_size;

        free(respbuffer);

	snprintf(mymsg, sizeof(mymsg), "TPM_SendLibTPMS: From TPM [%s]",
	         msg);

	showBuff(tb->buffer, mymsg);

        return 0;
}


static uint32_t TPM_ReceiveLibTPMS(int sockfd, struct tpm_buffer *tb)
{
	/*
	 * Doing everything in the transmit function
	 */
	(void)sockfd;
	(void)tb;
	return 0;
}

#endif /* TPM_USE_LIBTPMS */

