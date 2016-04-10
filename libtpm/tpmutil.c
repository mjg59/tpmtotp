/********************************************************************************/
/*										*/
/*			     	TPM Utility Functions				*/
/*			     Written by S. Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: tpmutil.c 4702 2013-01-03 21:26:29Z kgoldman $		*/
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
#include <stdarg.h>
#include <errno.h>

#include <unistd.h>     

#ifdef TPM_POSIX
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/types.h>
#include <fcntl.h>
#endif
#ifdef TPM_WINDOWS
#include <winsock2.h>
#endif

#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/aes.h>

#include "tpm.h"
#include "tpmfunc.h"
#include "tpm_types.h"
#include "tpm_constants.h"
#include "tpmutil.h"
#include "tpm_error.h"
#include "tpm_lowlevel.h"

/* local prototypes */
static void TPM_XOR(unsigned char *out,
                    const unsigned char *in1,
	            const unsigned char *in2,
	            size_t length);
static TPM_RESULT TPMC_SHA1_valist(TPM_DIGEST md,
                                   uint32_t length0, unsigned char *buffer0,
                                   va_list ap);

static TPM_RESULT TPMC_SHA1Init(void **context);
static TPM_RESULT TPMC_SHA1_Update(void *context, const unsigned char *data, uint32_t length);
static TPM_RESULT TPMC_SHA1Final(unsigned char *md, void *context);
static TPM_RESULT TPMC_SHA1Delete(void **context);

/* local variables */

static unsigned int logflag = 0;
/* the to-be-used lowlevel transport */
static struct tpm_transport *use_transp = NULL;
static int actual_used_transport = 0;

#ifdef TPM_USE_CHARDEV
static int preferred_transport = TPM_LOWLEVEL_TRANSPORT_CHARDEV;
#elif defined XCRYPTO_USE_CCA
static int preferred_transport = TPM_LOWLEVEL_TRANSPORT_CCA;
//#elif TPM_USE_LIBTPMS
//Never choose this as the default transport since programs will
//need to call TPMLIB_MainInit() themselves and possibly register
//callbacks with libtpms
//static int preferred_transport = TPM_LOWLEVEL_TRANSPORT_LIBTPMS;
#elif TPM_USE_UNIXIO
static int preferred_transport = TPM_LOWLEVEL_TRANSPORT_UNIXIO;
#else
static int preferred_transport = TPM_LOWLEVEL_TRANSPORT_TCP_SOCKET;
#endif


#ifdef TPM_USE_CHARDEV
static int use_vtpm = 0;
#else
static int use_vtpm = 0;
#endif


/****************************************************************************/
/*                                                                          */
/* Function to set the transport to be used.                                */
/*                                                                          */
/****************************************************************************/
struct tpm_transport *TPM_LowLevel_Transport_Set(struct tpm_transport *new_tp)
{
	struct tpm_transport *old = use_transp;
	use_transp = new_tp;
	return old;
}

/*
 * Initialize the low level transport layer to use the chosen
 * transport for communication with the TPM.
 * This function returns the actually chosen transport, which
 * may be different than the choice provided by the user, if
 * the transport chosen by the user was not compiled in.
 */
int TPM_LowLevel_Transport_Init(int choice)
{
	int tp = choice;

	if (tp == 0) {
		tp = preferred_transport;
	}

	switch (tp) {
		default:
		case TPM_LOWLEVEL_TRANSPORT_CHARDEV:
#ifdef TPM_POSIX
			use_vtpm = 0;
			TPM_LowLevel_TransportCharDev_Set();
#endif
		break;
		
		case TPM_LOWLEVEL_TRANSPORT_TCP_SOCKET:
			TPM_LowLevel_TransportSocket_Set();
		break;
		case TPM_LOWLEVEL_TRANSPORT_UNIXIO:
#ifdef TPM_POSIX		
			TPM_LowLevel_TransportUnixIO_Set();
#endif
		break;
		

#ifdef TPM_USE_LIBTPMS
                case TPM_LOWLEVEL_TRANSPORT_LIBTPMS:
                        TPM_LowLevel_TransportLibTPMS_Set();
                break;
#endif
	}
	actual_used_transport = tp;

	return tp;
}

int TPM_LowLevel_Use_VTPM(void)
{
	return use_vtpm;
}

int TPM_LowLevel_VTPM_Set(int state)
{
	int rc = use_vtpm;
	switch (actual_used_transport) {
		case TPM_LOWLEVEL_TRANSPORT_CHARDEV:
			if (state) {
				rc = -1;
			} else {
				use_vtpm = state;
			}
		break;
		default:
			use_vtpm = state;
		break;
	}
	return rc;
}

/****************************************************************************/
/*                                                                          */
/* Get the Size in a returned response                                      */
/*                                                                          */
/****************************************************************************/
uint32_t TSS_getsize(unsigned char *rsp)
{
    uint32_t size;
    size = LOAD32(rsp,TPM_PARAMSIZE_OFFSET);
    return size;
}

/****************************************************************************/
/*                                                                          */
/* Generate a random nonce                                                  */
/*                                                                          */
/****************************************************************************/
int TSS_gennonce(unsigned char *nonce)
{
    return RAND_bytes(nonce,TPM_HASH_SIZE);
}
   
/****************************************************************************/
/*                                                                          */
/*  This routine takes a format string, sort of analogous to sprintf,       */
/*  a buffer, and a variable number of arguments, and copies the arguments  */
/*  and data from the format string into the buffer, based on the characters*/
/*  in the format string.                                                   */
/*                                                                          */
/*  The routine returns a negative value if it detects an error in the      */
/*  format string, or a positive value containing the total length          */
/*  of the data copied to the buffer.                                       */
/*                                                                          */
/*  The legal characters in the format string are...                        */
/*                                                                          */
/*  0123456789abcdefABCDEF                                                  */
/*     These are used to insert bytes directly into the buffer, represented */
/*     in the format string as hex ASCII.  These MUST be in pairs,          */
/*     representing the two hex nibbles in a byte. e.g. C3 would insert     */
/*     a byte containing the hex value 0xC3 next position in the buffer.    */
/*     There is no argument associated with these format characters.        */
/*                                                                          */
/*  L                                                                       */
/*     This is used to insert the next argument into the buffer as a        */
/*     long (32 bit) unsigned word, in NETWORK byte order (big endian)      */
/*                                                                          */
/*  S                                                                       */
/*     This is used to insert the next argument into the buffer as a        */
/*     short (16 bit) unsigned word, in NETWORK byte order (big endian)     */
/*                                                                          */
/*                                                                          */
/*  l                                                                       */
/*     This is used to insert the next argument into the buffer as a        */
/*     long (32 bit) unsigned word, in NATIVE byte order.                   */
/*                                                                          */
/*  s                                                                       */
/*     This is used to insert the next argument into the buffer as a        */
/*     short (16 bit) unsigned word, in NATIVE byte order.                  */
/*                                                                          */
/*  o                                                                       */
/*     This is used to insert the next argument into the buffer as a        */
/*     byte or character                                                    */
/*                                                                          */
/*  @                                                                       */
/*     This is used to insert a sequence of bytes into the buffer, based    */
/*     on the next two arguments. The first is the length of the sequence.  */
/*     The second is a pointer to the array of bytes to be inserted.        */
/*     The length is inserted into the buffer as a 32 bit big-endian        */
/*     word, preceding the array.  If the length is 0, no array is          */
/*     copied, but the length word containing zero is inserted.             */
/*                                                                          */
/*  ^  This is used to insert a sequence of bytes into the buffer, based    */
/*     on the next two arguments. The first is the length of the sequence.  */
/*     The second is a pointer to the array of bytes to be inserted.        */
/*     The length is inserted into the buffer as a 16 bit big-endian        */
/*     word, preceding the array.  If the length is 0, no array is          */
/*     copied, but the length word containing zero is inserted.             */
/*                                                                          */
/*  %                                                                       */
/*     This is used to insert a sequence of bytes into the buffer, based    */
/*     on the next two arguments. The first is the length of the sequence.  */
/*     The second is a pointer to the array of bytes to be inserted.        */
/*     The length is NOT inserted into the buffer.                          */
/*                                                                          */
/*  T                                                                       */
/*     This is used to insert a 4 byte long value (32 bits, big endian)     */
/*     containing the total length of the data inserted into the buffer.    */
/*     There is no argument associated with this format character.          */
/*                                                                          */
/*                                                                          */
/*  Example                                                                 */
/*                                                                          */
/*   buildbuff("03Ts@99%",buf,10,6,"ABCDEF",3,"123");                       */
/*                                                                          */
/*   would produce a buffer containing...                                   */
/*                                                                          */
/*                                                                          */
/*   03 00 00 00 15 00 0A 00 00 00 06 41 42 43 44 45 46 99 31 32 33         */
/*                                                                          */
/*                                                                          */
/****************************************************************************/
int TSS_buildbuff(char *format,struct tpm_buffer *tb, ...)
{
    unsigned char *totpos;
    va_list argp;
    char *p;
    unsigned int totlen;
    unsigned char *o;
    unsigned long l;
    unsigned short s;
    unsigned char c;
    unsigned long len;
    uint16_t len16;
    unsigned char byte = 0;
    unsigned char hexflag;
    unsigned char *ptr;
    unsigned char *buffer = tb->buffer;
    unsigned int start = tb->used;
    int dummy;
   
    va_start(argp,tb);
    totpos = 0;
    totlen = tb->used;
    o = &buffer[totlen];
    hexflag = 0;
    p = format;
    while (*p != '\0')
	{
	    switch (*p)
		{
		  case ' ':
		    break;
		  case 'L':
		  case 'X':
		    if (hexflag) return ERR_BAD_ARG;
		    if (totlen + 4 >= tb->size) return ERR_BUFFER;
		    byte = 0;
		    l = (unsigned long)va_arg(argp,unsigned long);
		    STORE32(o,0,l);
		    if (*p == 'X')
		            va_arg(argp, unsigned long);
		    o += 4;
		    totlen += TPM_U32_SIZE;
		    break;
		  case 'S':
		    if (hexflag) return ERR_BAD_ARG;
		    if (totlen + 2 >= tb->size) return ERR_BUFFER;
		    byte = 0;
		    s = (unsigned short)va_arg(argp,int);
		    STORE16(o,0,s);
		    o += TPM_U16_SIZE;
		    totlen += TPM_U16_SIZE;
		    break;
		  case 'l':
		    if (hexflag) return ERR_BAD_ARG;
		    if (totlen + 4 >= tb->size) return ERR_BUFFER;
		    byte = 0;
		    l = (unsigned long)va_arg(argp,unsigned long);
		    STORE32N(o,0,l);
		    o += TPM_U32_SIZE;
		    totlen += TPM_U32_SIZE;
		    break;
		  case 's':
		    if (hexflag) return ERR_BAD_ARG;
		    if (totlen + 2 >= tb->size) return ERR_BUFFER;
		    byte = 0;
		    s = (unsigned short)va_arg(argp,int);
		    STORE16N(o,0,s);
		    o += TPM_U16_SIZE;
		    totlen += TPM_U16_SIZE;
		    break;
		  case 'o':
		    if (hexflag) return ERR_BAD_ARG;
		    if (totlen + 1 >= tb->size) return ERR_BUFFER;
		    byte = 0;
		    c = (unsigned char)va_arg(argp,int);
		    *(o) = c;
		    o += 1;
		    totlen += 1;
		    break;
		  case '@':
		  case '*':
		    if (hexflag) return ERR_BAD_ARG;
		    byte = 0;
		    len = (int)va_arg(argp,int);
		    if (totlen + 4 + len >= tb->size) return ERR_BUFFER;
		    ptr = (unsigned char *)va_arg(argp,unsigned char *);
		    if (len > 0 && ptr == NULL) return ERR_NULL_ARG;
		    STORE32(o,0,len);
		    o += TPM_U32_SIZE;
		    if (len > 0) memcpy(o,ptr,len);
		    o += len;
		    totlen += len + TPM_U32_SIZE;
		    break;
		  case '&':
		    if (hexflag) return ERR_BAD_ARG;
		    byte = 0;
		    len16 = (uint16_t)va_arg(argp,int);
		    if (totlen + 2 + len16 >= tb->size) return ERR_BUFFER;
		    ptr = (unsigned char *)va_arg(argp,unsigned char *);
		    if (len16 > 0 && ptr == NULL) return ERR_NULL_ARG;
		    STORE16(o,0,len16);
		    o += TPM_U16_SIZE;
		    if (len16 > 0) memcpy(o,ptr,len16);
		    o += len16;
		    totlen += len16 + TPM_U16_SIZE;
		    break;
		  case '%':
		    if (hexflag) return ERR_BAD_ARG;
		    byte = 0;
		    len = (int)va_arg(argp,int);
		    if (totlen + len >= tb->size) return ERR_BUFFER;
		    ptr = (unsigned char *)va_arg(argp,unsigned char *);
		    if (len > 0 && ptr == NULL) return ERR_NULL_ARG;
		    if (len > 0) memcpy(o,ptr,len);
		    o += len;
		    totlen += len;
		    break;
		  case 'T':
		    if (hexflag) return ERR_BAD_ARG;
		    if (totlen + 4 >= tb->size) return ERR_BUFFER;
		    byte = 0;
		    totpos = o;
		    o += TPM_U32_SIZE;
		    totlen += TPM_U32_SIZE;
		    break;
		  case '0':
		  case '1':
		  case '2':
		  case '3':
		  case '4':
		  case '5':
		  case '6':
		  case '7':
		  case '8':
		  case '9':
		    if (totlen + 1 >= tb->size) return ERR_BUFFER;
		    byte = byte << 4;
		    byte = byte |  ((*p - '0') & 0x0F);
		    if (hexflag)
			{
			    *o = byte;
			    ++o;
			    hexflag = 0;
			    totlen += 1;
			}
		    else ++hexflag;
		    break;
		  case 'A':
		  case 'B':
		  case 'C':
		  case 'D':
		  case 'E':
		  case 'F':
		    if (totlen + 1 >= tb->size) return ERR_BUFFER;
		    byte = byte << 4;
		    byte = byte |  (((*p - 'A') & 0x0F) + 0x0A);
		    if (hexflag)
			{
			    *o = byte;
			    ++o;
			    hexflag = 0;
			    totlen += 1;
			}
		    else ++hexflag;
		    break;
		  case 'a':
		  case 'b':
		  case 'c':
		  case 'd':
		  case 'e':
		  case 'f':
		    if (totlen + 1 >= tb->size) return ERR_BUFFER;
		    byte = byte << 4;
		    byte = byte |  (((*p - 'a') & 0x0F) + 0x0A);
		    if (hexflag)
			{
			    *o = byte;
			    ++o;
			    hexflag = 0;
			    totlen += 1;
			}
		    else ++hexflag;
		    break;
		  case '^': 
		            /* the size indicator is only 16 bits long */
		            /* parameters: address of length indicator,
		               maximum number of bytes
		               address of buffer  */
		    if (hexflag) return ERR_BAD_ARG;
		    byte = 0;
		    len16 = (uint16_t)va_arg(argp, int);
		    dummy = va_arg(argp, int);
		    dummy = dummy; /* make compiler happy */
		    if (totlen + len16 >= tb->size) return ERR_BUFFER;
		    ptr = (unsigned char *)va_arg(argp,unsigned char *);
		    if (len16 > 0 && ptr == NULL) return ERR_NULL_ARG;
		    STORE16(o,0,len16);
		    o += TPM_U16_SIZE;
		    if (len16 > 0) memcpy(o,ptr,len16);
		    o += len16;
		    totlen += TPM_U16_SIZE + len16;
		    break;
		  case '!': 
		            /* the size indicator is 32 bytes long */
		            /* parameters: address of length indicator,
		               maximum number of bytes
		               address of buffer  */
		    if (hexflag) return ERR_BAD_ARG;
		    byte = 0;
		    len = va_arg(argp,int);
		    dummy = va_arg(argp, int);
		    if (totlen + len >= tb->size) return ERR_BUFFER;
		    ptr = (unsigned char *)va_arg(argp,unsigned char *);
		    if (len > 0 && ptr == NULL) return ERR_NULL_ARG;
		    STORE32(o,0,len);
		    o += TPM_U32_SIZE;
		    if (len > 0) memcpy(o,ptr,len);
		    o += len;
		    totlen += TPM_U32_SIZE + len;
		    break;
		  case '#': 
		            /* reverse write the buffer (good for 'exponent') */
		            /* the size indicator is 32 bytes long */
		            /* parameters: address of length indicator,
		               maximum number of bytes
		               address of buffer  */
		    if (hexflag) return ERR_BAD_ARG;
		    byte = 0;
		    len = va_arg(argp,int);
		    dummy = va_arg(argp, int);
		    if (totlen + len >= tb->size) return ERR_BUFFER;
		    ptr = (unsigned char *)va_arg(argp,unsigned char *);
		    if (len > 0 && ptr == NULL) return ERR_NULL_ARG;
		    STORE32(o,0,len);
		    o += TPM_U32_SIZE;
		    totlen += TPM_U32_SIZE + len;
		    while (len > 0) {
		        *o = ptr[len-1];
		        o++;
		        len--;
		    }
		    break;
		  default:
		    return ERR_BAD_ARG;
		}
	    ++p;
	}
    if (totpos != 0) STORE32(totpos,0,totlen);
    va_end(argp);
#ifdef DEBUG
    printf("buildbuff results...\n");
    for (i=0; i < totlen; i++)
	{
	    if (i && !( i % 16 ))
		{
		    printf("\n");
		}
	    printf("%.2X ",buffer[i]);
	}
    printf("\n");
#endif
    tb->used = totlen;
    return totlen-start;
}

int TSS_parsebuff(char *format,const struct tpm_buffer *tb, uint32_t start,...)
{
    va_list argp;
    char *p;
    unsigned int offset;
    uint32_t *l;
    uint16_t *s;
    unsigned char *c;
    uint32_t *len;
    uint16_t *len16;
    uint32_t lenmax;
    unsigned int length;
    unsigned char *ptr;
    unsigned char **pptr;
    uint32_t tmp;
    uint32_t ret;
    unsigned char *buf;
   
    va_start(argp,start);
    offset = start;
    p = format;
    while (*p != '\0')
	{
	    switch (*p)
		{
		  case ' ':
		    break;
		  case 'L':
		    l = (uint32_t *)va_arg(argp,unsigned long *);
		    ret = tpm_buffer_load32(tb,offset,l);
		    if ((ret & ERR_MASK)) {
		      return ret;
		    }
		    offset += TPM_U32_SIZE;
		    break;
		  case 'X':
		    tmp = (uint32_t)va_arg(argp, int);
		    tmp = tmp; /* make compiler happy */
		    l = (uint32_t *)va_arg(argp, unsigned long *);
		    ret = tpm_buffer_load32(tb,offset,l);
		    if ((ret & ERR_MASK)) {
		      return ret;
		    }
		    offset += TPM_U32_SIZE;
		    break;
		  case 'S':
		    s = (uint16_t *)va_arg(argp,int *);
		    ret = tpm_buffer_load16(tb,offset,s);
		    if ((ret & ERR_MASK)) {
		      return ret;
		    }
		    offset += TPM_U16_SIZE;
		    break;
		  case 'l':
		    l = (uint32_t *)va_arg(argp,unsigned long *);
		    ret = tpm_buffer_load32N(tb,offset,l);
		    if ((ret & ERR_MASK)) {
		      return ret;
		    }
		    offset += TPM_U32_SIZE;
		    break;
		  case 's':
		    s = (uint16_t *)va_arg(argp,int *);
		    ret = tpm_buffer_load16N(tb,offset,s);
		    if ((ret & ERR_MASK)) {
		      return ret;
		    }
		    offset += TPM_U16_SIZE;
		    break;
		  case 'o':
		    if (offset + 1 > tb->used) return ERR_BUFFER;
		    c = (unsigned char *)va_arg(argp,unsigned char *);
		    *c = tb->buffer[offset];
		    offset += 1;
		    break;
		  case '@':
		    len = (uint32_t *)va_arg(argp,int *);
		    ret = tpm_buffer_load32(tb,offset,len);
		    if ((ret & ERR_MASK)) {
		      return ret;
		    }
		    offset += 4;
		    ptr = (unsigned char *)va_arg(argp,unsigned char *);
		    if (*len > 0 && ptr == NULL) return -3;
		    if (offset + *len > tb->used) return ERR_BUFFER;
		    if (*len > 0) memcpy(ptr,&tb->buffer[offset],*len);
		    offset += *len;
		    break;
		  case '*': /* a sized buffer with 32bit size indicator whose
		               buffer needs to be allocated */
		    len = (uint32_t *)va_arg(argp,int *);
		    ret = tpm_buffer_load32(tb,offset,len);
		    if ((ret & ERR_MASK)) {
		      return ret;
		    }
		    offset += 4;
		    pptr = (unsigned char **)va_arg(argp,unsigned char **);
		    if (*len > 0 && pptr == NULL) return -3;
		    if (offset + *len > tb->used) return ERR_BUFFER;
		    if (*len > 0) {
		    	buf = malloc(*len);
		    	if (NULL == buf) return ERR_MEM_ERR; 
			*pptr = buf;
		        memcpy(buf,&tb->buffer[offset],*len);
		    }
		    offset += *len;
		    break;
		  case '&': /* a sized buffer with 16bit size indicator whose
		               buffer needs to be allocated */
		    len16 = (uint16_t *)va_arg(argp,uint16_t *);
		    ret = tpm_buffer_load16(tb,offset,len16);
		    if ((ret & ERR_MASK)) {
		      return ret;
		    }
		    offset += 2;
		    pptr = (unsigned char **)va_arg(argp,unsigned char **);
		    if (*len16 > 0 && pptr == NULL) return -3;
		    if (offset + *len16 > tb->used) return ERR_BUFFER;
		    if (*len16 > 0) {
		    	buf = malloc(*len16);
		    	if (NULL == buf) return ERR_MEM_ERR; 
			*pptr = buf;
		        memcpy(buf,&tb->buffer[offset],*len16);
		    }
		    offset += *len16;
		    break;
		  case '^': /* a sized buffer structure whose buffer is available */
		            /* the size indicator is only 16 bits long */
		            /* parameters: address of length indicator,
		               maximum number of bytes
		               address of buffer  */
		    len16 = (uint16_t *)va_arg(argp,uint16_t *);
		    lenmax =va_arg(argp, int);
		    ret = tpm_buffer_load16(tb,offset,len16);
		    if ((ret & ERR_MASK)) {
		      return ret;
		    }
		    offset += 2;
		    ptr = (unsigned char *)va_arg(argp,unsigned char *);
		    if (*len16 > 0 && ptr == NULL) return ERR_BUFFER;
		    if (offset + *len16 > tb->used) return ERR_BUFFER;
		    if (*len16 > lenmax) return ERR_BUFFER;
		    if (*len16 > 0) {
		        memcpy(ptr,&tb->buffer[offset],*len16);
		    }
		    offset += *len16;
		    break;
		  case '!': /* a sized buffer structure whose buffer needs to be allocated */
		            /* the size indicator is 32 bits long */
		            /* parameters: address of length indicator,
		               maximum number of bytes
		               address of buffer  */
		    len = (uint32_t *)va_arg(argp,int *);
		    lenmax =va_arg(argp, int);
		    ret = tpm_buffer_load32(tb,offset,len);
		    if ((ret & ERR_MASK)) {
		      return ret;
		    }
		    offset += TPM_U32_SIZE;
		    ptr = (unsigned char *)va_arg(argp,unsigned char *);
		    if (*len > 0 && ptr == NULL) return -3;
		    if (offset + *len > tb->used) return ERR_BUFFER;
		    if (*len > lenmax) return ERR_BUFFER;
		    if (*len > 0) {
		        memcpy(ptr,&tb->buffer[offset],*len);
		    }
		    offset += *len;
		    break;
		  case '#': /* a sized buffer structure whose buffer needs to be allocated */
		            /* reverse the data (good for 'exponent') */
		            /* the size indicator is 32 bits long */
		            /* parameters: address of length indicator,
		               maximum number of bytes
		               address of buffer  */
		    len = (uint32_t *)va_arg(argp,int *);
		    lenmax =va_arg(argp, int);
		    ret = tpm_buffer_load32(tb,offset,len);
		    if ((ret & ERR_MASK)) {
		      return ret;
		    }
		    offset += TPM_U32_SIZE;
		    ptr = (unsigned char *)va_arg(argp,unsigned char *);
		    if (*len > 0 && ptr == NULL) return -3;
		    if (offset + *len > tb->used) return ERR_BUFFER;
		    if (*len > lenmax) return ERR_BUFFER;
		    length = *len;
		    while (length > 0) {
		        *ptr = tb->buffer[offset+length-1];
		        length--;
		        ptr++;
		    }
		    offset += *len;
		    break;
		  case '%':
		    length = (int)va_arg(argp,int);
		    if (offset + length > tb->used) return ERR_BUFFER;
		    ptr = (unsigned char *)va_arg(argp,unsigned char *);
		    if (length > 0 && ptr == NULL) return ERR_NULL_ARG;
		    if (length > 0) memcpy(ptr,&tb->buffer[offset],length);
		    offset += length;
		    ptr=NULL;
		    break;
		  default:
		    return ERR_BAD_ARG;
		}
	    ++p;
	}
    va_end(argp);

    return offset-start;
}

/****************************************************************************/
/*                                                                          */
/*  optional verbose logging of data to/from tpm chip                       */
/*                                                                          */
/****************************************************************************/
void showBuff(unsigned char* buff, char* string)
{
    uint32_t i,len;
    uint32_t addsize = 0;
    if (use_vtpm) {
        addsize = 4;
    }

    if (!logflag) return;
    len = addsize + LOAD32(buff,addsize+TPM_PARAMSIZE_OFFSET);

    printf("%s length=%d\n", string,(int)len);
    for (i=0; i < len; i++)
	{
	    if (i && !( i % 16 ))
		{
		    printf("\n");
		}
	    printf("%.2X ",buff[i]);
	}
    printf("\n");
}



/****************************************************************************/
/*									  */
/* Transmit request to TPM and read Response				*/
/*									  */
/****************************************************************************/

uint32_t TPM_Send(struct tpm_buffer *tb,const char *msg) {
	uint32_t rc = 0;
	int sock_fd;
	
	if (!actual_used_transport) {
		TPM_LowLevel_Transport_Init(0);
	}
	
	/* To emulate the real behavior, open and close the socket each
	   time.  If this kills performance, we can introduce a static and
	   keep the socket open. */
	if (rc == 0) {
	    rc = use_transp->open(&sock_fd);
	}
	if (rc == 0) {
	    if (logflag) printf("\nTPM_Send: %s\n", msg);
	    rc = use_transp->send(sock_fd, tb, msg);
	}
	if (rc == 0) {
	    rc = use_transp->recv(sock_fd, tb);
	}
	use_transp->close(sock_fd);
	return rc;
}


static uint32_t createTransport(session *transSession, uint32_t *in_tp)
{
	uint32_t ret = 0;
	char *tpm_transport     = getenv("TPM_TRANSPORT");
	char *tpm_transport_ek  = getenv("TPM_TRANSPORT_EK");
	char *tpm_transport_ekp = getenv("TPM_TRANSPORT_EKP");
	char *tpm_transport_pass= getenv("TPM_TRANSPORT_PASS");
	char *tpm_transport_handle = getenv("TPM_TRANSPORT_HANDLE");
	*in_tp = 0;
	if (tpm_transport     &&
	    0 == strcmp("1",tpm_transport) &&
	    tpm_transport_ek  &&
	    tpm_transport_ekp &&
	    tpm_transport_pass ) {
		uint32_t ekhandle;
		TPM_TRANSPORT_PUBLIC ttp;
		TPM_TRANSPORT_AUTH tta;
		unsigned char *keyPassHashPtr = NULL;
		unsigned char keyPassHash[TPM_HASH_SIZE];
		unsigned char *transPassHashPtr = NULL;
		unsigned char transPassHash[TPM_HASH_SIZE];
		TPM_CURRENT_TICKS currentTicks;
		int i;
		STACK_TPM_BUFFER(buffer)
		STACK_TPM_BUFFER(secret)
		RSA *rsa;
		pubkeydata pubkey;

		if (1 != sscanf(tpm_transport_ek,"%x",&ekhandle)) {
			return ERR_BAD_ARG;
		}

		if (tpm_transport_ekp) {
			TSS_sha1((unsigned char *)tpm_transport_ekp,
				 strlen(tpm_transport_ekp),
				 keyPassHash);
			keyPassHashPtr = keyPassHash;
		}

		if (tpm_transport_pass) {
			TSS_sha1((unsigned char *)tpm_transport_pass,
				 strlen(tpm_transport_pass),
				 transPassHash);
			transPassHashPtr = transPassHash;
		}
		ttp.tag = TPM_TAG_TRANSPORT_PUBLIC;
		ttp.transAttributes = TPM_TRANSPORT_ENCRYPT|TPM_TRANSPORT_LOG;

		_TPM_getTransportAlgIdEncScheme(&ttp.algId, &ttp.encScheme);

		ret = TPM_GetPubKey_UseRoom(ekhandle,
				            keyPassHashPtr,
				            &pubkey);
		if (ret != 0) {
			printf("tpmutil: Error '%s' from TPM_GetPubKey_UseRoom(0x%08x)\n",
			       TPM_GetErrMsg(ret), ekhandle);
			return ret;
		}
		rsa = TSS_convpubkey(&pubkey);

		tta.tag = TPM_TAG_TRANSPORT_AUTH;
		for (i = 0; i < TPM_AUTHDATA_SIZE; i ++) {
			tta.authData[i] = transPassHashPtr[i];
		}
		TPM_WriteTransportAuth(&buffer, &tta);

		secret.used = secret.size;
		TSS_Bind(rsa, &buffer, &secret);

		ret = TPM_EstablishTransport_UseRoom(ekhandle,
                                                     keyPassHashPtr,
		                                     &ttp,
		                                     transPassHashPtr,
		                                     &secret,
		                                     &currentTicks,
                                                     transSession);
		if (ret == 0) {
			uint32_t idx = 1;
			TSS_PushTransportFunction(TPM_ExecuteTransport,
						  &idx);

			TSS_SetTransportParameters(transSession, idx);															  
		} else {
			printf("Error %s from EstablishTransport.\n",
			       TPM_GetErrMsg(ret));
		}
		ret = 0;
		*in_tp = 1;
	} else
	if (tpm_transport     &&
	    0 == strcmp("2",tpm_transport) &&
	    tpm_transport_pass &&
	    tpm_transport_handle ) {
		unsigned char transPassHash[TPM_HASH_SIZE];
		unsigned char * transnonce;
		uint32_t transNonceSize;
		uint32_t transhandle;
		uint32_t ret;
		uint32_t idx;

		ret = parseHash((char *)tpm_transport_pass,
				transPassHash);
		if ((ret & ERR_MASK)) {
			return ret;
		}
		
		ret = TPM_ReadFile(".enonce",
				   &transnonce,
				   &transNonceSize);

		if ((ret & ERR_MASK)) {
			return ret;
		}
		
		if (1 != sscanf(tpm_transport_handle,
				"%x",
				&transhandle)) {
			return ERR_BAD_ARG;
		}

		TSS_Session_CreateTransport(transSession,
					    transPassHash,
					    transhandle,
					    transnonce);
		TSS_PushTransportFunction(TPM_ExecuteTransport,
					  &idx);

		TSS_SetTransportParameters(transSession, idx);
		*in_tp = 1;
	} else {
	    if ((tpm_transport && !strcmp("1",tpm_transport) &&
		 (!tpm_transport_ek  || 
		  !tpm_transport_ekp ||
		  !tpm_transport_pass) 
		) ||
		(tpm_transport && !strcmp("2",tpm_transport) &&
		 (!tpm_transport_pass || !tpm_transport_handle)
		)
	       ) {
#if 0
		printf("Something is wrong with the environment variables:\n"
		       "TPM_TRANSPORT	= %s\n"
		       "TPM_TRANSPORT_EK     = %s\n"
		       "TPM_TRANSPORT_EKP    = %s\n"
		       "TPM_TRANSPORT_PASS   = %s\n"
		       "TPM_TRANSPORT_HANDLE = %s\n",
		       tpm_transport,
		       tpm_transport_ek,
		       tpm_transport_ekp,
		       tpm_transport_pass,
		       tpm_transport_handle);
#endif
//		ret = ERR_ENV_VARIABLE;
	    }
	}
	return ret;
}

static uint32_t destroyTransport(session *transSession)
{
	uint32_t ret = 0;
	char *tpm_transport     = getenv("TPM_TRANSPORT");
	char *tpm_transport_sk  = getenv("TPM_TRANSPORT_SK");
	char *tpm_transport_skp = getenv("TPM_TRANSPORT_SKP");
	if (tpm_transport     &&
	    0 == strcmp("1",tpm_transport) &&
	    tpm_transport_sk &&
	    tpm_transport_skp) {
		unsigned char *keyPassHashPtr = NULL;
		unsigned char keyPassHash[TPM_HASH_SIZE];
		uint32_t skhandle;
		unsigned char antiReplay[TPM_NONCE_SIZE];
		uint32_t idx = 0;
		STACK_TPM_BUFFER (signature);

		if (1 != sscanf(tpm_transport_sk,"%x",&skhandle)) {
			return ERR_BAD_ARG;
		}

		if (tpm_transport_skp) {
			TSS_sha1((unsigned char *)tpm_transport_skp,
				 strlen(tpm_transport_skp),
				 keyPassHash);
			keyPassHashPtr = keyPassHash;

		}
		TSS_PopTransportFunction(&idx);

		ret = TPM_ReleaseTransportSigned(skhandle,
						 keyPassHashPtr,
						 transSession,
						 antiReplay,
						 &signature,
						 NULL);
	} else
	if (tpm_transport &&
	    0 == strcmp("2",tpm_transport)) {
	    	uint32_t idx = 0;
		ret = TPM_WriteFile(".enonce",
				    TSS_Session_GetENonce(transSession),
				    TPM_NONCE_SIZE);
		TSS_PopTransportFunction(&idx);
	}
	return ret;
}

extern uint32_t (*g_transportFunction[])(struct tpm_buffer *tb,
					 const char *msg);
extern uint32_t g_num_transports;


static uint32_t TPM_Transmit_Internal(struct tpm_buffer *tb,const char *msg,
                                      int allowTransport)
{
    uint32_t rc = 0, irc;
    static int transport_created = 0;

    if (0 == transport_created) {
	uint32_t ord = 0;
	session sess;
	tpm_buffer_load32(tb, 6, &ord);
	transport_created = 1;
	if (allowTransport && allowsTransport(ord)) {
	    uint32_t in_tp;
	    irc = 0;
	    /* 
	       don't have createTransport assign irc
	       it also is called if the transport is invalid 
	       in_tp returns '1' if the transport should be destroyed
	     */
	    createTransport(&sess, &in_tp);
	    if (irc == 0) {
		 rc = TPM_Transmit(tb,msg);
	    }
	    if (in_tp) {
		/* don't assign it the return value! It works fine 
		   without propagating possible errors upwards.*/
		/*irc =*/ destroyTransport(&sess);
	    }
	    if (irc != 0) {
		rc = irc;
	    }
	} else {
	    rc = TPM_Transmit(tb,msg);
	}
	transport_created = 0;
	return rc;
    }

    if (g_num_transports > 0 && NULL != g_transportFunction[g_num_transports-1]) {
	--g_num_transports;
	/*
	 * I cannot do the auditing here. Must do this in
	 * all transports separately.
	 */
	rc = g_transportFunction[g_num_transports](tb, msg);
	if (0 == rc) {
	    /*
	     * Transport function was doing OK, so let me see whether
	     * the caller also did OK.
	     */
	    tpm_buffer_load32(tb, TPM_RETURN_OFFSET, &rc);
	}
	g_num_transports++;
    } else {
    	char mesg[1024];
	unsigned int inst = 0;
	unsigned int locty = 0;
	uint16_t tag_out = 0;
	uint16_t tag_in = 0;
	uint32_t ordinal = 0;
	unsigned int tagoffset = 0;
	unsigned char *buff = tb->buffer;
	uint32_t resp_result = 0;
	struct tpm_buffer *orig_request;
	/*
	 * NEVER prepend anything when using a chardev since I could be
	 * talking to a hardware TPM. If I am talking to a chardev in
	 * a virtualized system, the prepending will happen on the
	 * receiving side in the driver layer.
	 * DO prepend for sockets - assumption is that such a TPM does
	 * not really exits and we are only using this for testing
	 * purposes.
	 */
	unsigned int ret_inst = 0;
	char * instance = getenv("TPM_INSTANCE");
	char * locality = getenv("TPM_USE_LOCALITY");
	tpm_buffer_load32(tb, 6, &ordinal);

#if 0
        /* older specs always audited independent of result return code */
	_TPM_AuditInputstream(tb,0);
#else
        /* newer specs require late auditing since only audited upon success */
        orig_request = clone_tpm_buffer(tb);
#endif

	if (use_vtpm) {
	    /*
	     * Check whether an instance of the TPM is to be used.
	     */
	    if (NULL != instance) {
		inst = (unsigned int)atoi(instance);
	    }
	    if (NULL != locality) {
		locty = (unsigned int)atoi(locality);
		if (locty > 4) {
		    locty = 0;
		}
		/* add locality into bits 31-29 of instance identifier */
		inst = (inst & 0x1fffffff) | (locty << 29);
	    }
	    if (tb->used + 4 >= tb->size) {
	        TSS_FreeTPMBuffer(orig_request);
		return -1;
	    }
	    memmove(&buff[4], &buff[0], tb->used);
	    buff[0] = (inst >> 24) & 0xff;
	    buff[1] = (inst >> 16) & 0xff;
	    buff[2] = (inst >>  8) & 0xff;
	    buff[3] = (inst >>  0) & 0xff;
	    tb->used += 4;

	    tagoffset = 4;
	}

	tpm_buffer_load16(tb, tagoffset, &tag_out);
	if (use_vtpm)
	    sprintf(mesg,"%s (instance=%d, locality=%d)",msg,inst,locty);
	else
	    sprintf(mesg,"%s", msg);
	rc = TPM_Send(tb, mesg);

	if (actual_used_transport != TPM_LOWLEVEL_TRANSPORT_CHARDEV) {
	    /* 
	     * For some reason the HW TPM seems to return a wrong initial byte
	     * when doing a Quote(). So I have to deactivate this part here
	     * when talking to a chardev!
	     */
	    if (0 == rc) {
		tpm_buffer_load16(tb, tagoffset, &tag_in);
		if ((tag_in - 3)  != tag_out) {
		    rc = ERR_BADRESPONSETAG;
		}
	    }
	}

	if (use_vtpm) {
	    /*
	     * Only when using character device I do not expect the instance number to come back
	     */
	    ret_inst = ntohl( *((uint32_t *)&buff[0]) );
	    if (inst != ret_inst) {
		printf("Returned instance bad (0x%x != 0x%x)\n",inst,ret_inst);
		return -1;
	    }
	    tb->used -= 4;
	    memmove(&buff[0], &buff[4], tb->used);
	}

#if 0
	_TPM_AuditOutputstream(tb, ordinal, 0);
#else
        tpm_buffer_load32(tb, 6, &resp_result);
        if (resp_result == 0 ) {
            _TPM_AuditInputstream(orig_request, 0);
            _TPM_AuditOutputstream(tb, ordinal, 0);
        }
#endif

	if (0 == rc) {
	    uint32_t used = 0;
	    tpm_buffer_load32(tb, 2, &used);
	    if (tb->used != used) {
		rc = ERR_BAD_RESP;
	    }
	}
	if (0 == rc) {
	    tpm_buffer_load32(tb, TPM_RETURN_OFFSET, &rc);
	}

        TSS_FreeTPMBuffer(orig_request);
    }
    return rc;
}


uint32_t TPM_Transmit(struct tpm_buffer *tb,const char *msg)
{
    return TPM_Transmit_Internal(tb, msg, 1);
}

uint32_t TPM_Transmit_NoTransport(struct tpm_buffer *tb,const char *msg)
{
    return TPM_Transmit_Internal(tb, msg, 0);
}

 
/****************************************************************************/
/*									  */
/* Perform a SHA1 hash on a single buffer				   */
/*									  */
/****************************************************************************/
void TSS_sha1(void *input, unsigned int len, unsigned char *output)
{
	SHA_CTX sha;
   
	SHA1_Init(&sha);
	SHA1_Update(&sha,input,len);
	SHA1_Final(output,&sha);
}

/****************************************************************************/
/*									  */
/* Perform a SHA1 hash on a file					    */
/*									  */
/****************************************************************************/
uint32_t TSS_SHAFile(const char *filename, unsigned char *buffer)
{
	uint32_t ret = 0;
	FILE *f;
	f = fopen(filename, "r");
	
	if (NULL != f) {
		size_t len;
		unsigned char mybuffer[10240];
		SHA_CTX sha;
		SHA1_Init(&sha);
		do {
			len = fread(mybuffer, 1, sizeof(mybuffer), f);
			if (len) {
				SHA1_Update(&sha, mybuffer, len);
			}
		} while (len == sizeof(mybuffer));
		fclose(f);
		SHA1_Final(buffer, &sha);
	} else {
		ret = ERR_BAD_FILE;
	}
	return ret;
}

/****************************************************************************/
/*									  */
/* set logging flag							 */
/*									  */
/****************************************************************************/
int TPM_setlog(int flag)
{
	int old;
	char *dump = getenv("TPM_DUMP_COMMANDS");
	
	old = logflag;
	/* user has control if TPM_DUMP_COMMANDS == "0" */
	if (NULL == dump || strcmp(dump,"0") == 0)
		logflag = flag;
	return old;
}

uint32_t tpm_buffer_load32(const struct tpm_buffer *tb, uint32_t off, uint32_t *val)
{
	if (off + 3 >= tb->used) {
		return ERR_BUFFER;
	}
	*val = LOAD32(tb->buffer, off);
	return 0;
}

uint32_t tpm_buffer_store32(struct tpm_buffer *tb, uint32_t val)
{
	if (tb->used + 4 > tb->size) {
		return ERR_BUFFER;
	}
	STORE32(tb->buffer, tb->used, val);
	tb->used += 4;
	return 0;
}

uint32_t tpm_buffer_load32N(const struct tpm_buffer *tb, uint32_t off, uint32_t *val)
{
	if (off + 3 >= tb->used) {
		return ERR_BUFFER;
	}
	*val = LOAD32N(tb->buffer, off);
	return 0;
}

uint32_t tpm_buffer_load16(const struct tpm_buffer *tb, uint32_t off, uint16_t *val)
{
	if (off + 1 >= tb->used) {
		return ERR_BUFFER;
	}
	*val = LOAD16(tb->buffer, off);
	return 0;
}

uint32_t tpm_buffer_load16N(const struct tpm_buffer *tb, uint32_t off, uint16_t *val)
{
	if (off + 1 >= tb->used) {
		return ERR_BUFFER;
	}
	*val = LOAD16N(tb->buffer, off);
	return 0;
}

uint32_t tpm_buffer_store(struct tpm_buffer *dest, struct tpm_buffer *src,
                          uint32_t soff, uint32_t slen)
{
	if (dest->used + slen > dest->size ||
	    soff + slen > src->size) {
	    	return ERR_BUFFER;
	}
	memcpy(&dest->buffer[dest->used],
	       &src ->buffer[soff],
	       slen);
        dest->used += slen;
	return 0;
} 

uint32_t parseHash(char *string, unsigned char *hash)
{
	uint32_t ret = 0;
	uint32_t i = 0;
	unsigned char byte = 0;
	while (i < 40) {
		byte <<= 4;
		if (string[i] >= '0' && string[i] <= '9') {
			byte |= string[i] - '0';
		} else
		if (string[i] >= 'A' && string[i] <= 'F') {
			byte |= string[i] - 'A' + 10;
		} else
		if (string[i] >= 'a' && string[i] <= 'f') {
			byte |= string[i] - 'a' + 10;
		} else {
			return 1;
		}
		hash[i/2] = byte;
		i++;
	}
	return ret;
}

/****************************************************************************/
/*									  */
/* AES CTR mode - non-standard TPM increment				*/
/*									  */
/****************************************************************************/

/* TPM_AES_ctr128_encrypt() is a TPM variant of the openSSL AES_ctr128_encrypt() function that
   increments only the low 4 bytes of the counter.

   openSSL increments the entire CTR array.  The TPM does not follow that convention.
*/

TPM_RESULT TPM_AES_ctr128_Encrypt(unsigned char *data_out,
				  const unsigned char *data_in,
				  unsigned long data_size,
				  const AES_KEY *aes_enc_key,
				  unsigned char ctr[TPM_AES_BLOCK_SIZE])
{
    TPM_RESULT 	rc = 0;
    uint32_t cint;
    unsigned char pad_buffer[TPM_AES_BLOCK_SIZE];	/* the XOR pad */

    while (data_size != 0) {
	/* get an XOR pad array by encrypting the CTR with the AES key */
	AES_encrypt(ctr, pad_buffer, aes_enc_key);
	/* partial or full last data block */
	if (data_size <= TPM_AES_BLOCK_SIZE) {
	    TPM_XOR(data_out, data_in, pad_buffer, data_size);
	    data_size = 0;
	}
	/* full block, not the last block */
	else {
	    TPM_XOR(data_out, data_in, pad_buffer, TPM_AES_BLOCK_SIZE);
	    data_in += TPM_AES_BLOCK_SIZE;
	    data_out += TPM_AES_BLOCK_SIZE;
	    data_size -= TPM_AES_BLOCK_SIZE;
	}
	/* if not the last block, increment CTR */
	if (data_size != 0) {
	    cint = LOAD32(ctr, 12);	/* byte array to uint32_t */
	    cint++;			/* increment */
	    STORE32(ctr, 12, cint);	/* uint32_t to byte array */
	}
    }
    return rc;
}


/* TPM_XOR XOR's 'in1' and 'in2' of 'length', putting the result in 'out'

 */

static void TPM_XOR(unsigned char *out,
		    const unsigned char *in1,
		    const unsigned char *in2,
		    size_t length)
{
    size_t i;
    
    for (i = 0 ; i < length ; i++) {
	out[i] = in1[i] ^ in2[i];
    }
    return;
}

/* TSS_MGF1() generates an MGF1 'array' of length 'arrayLen' from 'seed' of length 'seedlen'

   The openSSL DLL doesn't export MGF1 in Windows or Linux 1.0.0, so this version is created from
   scratch.
   
   Algorithm and comments (not the code) from:

   PKCS #1: RSA Cryptography Specifications Version 2.1 B.2.1 MGF1

   Prototype designed to be compatible with openSSL

   MGF1 is a Mask Generation Function based on a hash function.
   
   MGF1 (mgfSeed, maskLen)

   Options:     

   Hash hash function (hLen denotes the length in octets of the hash 
   function output)

   Input:
   
   mgfSeed         seed from which mask is generated, an octet string
   maskLen         intended length in octets of the mask, at most 2^32(hLen)

   Output:      
   mask            mask, an octet string of length l; or "mask too long"

   Error:          "mask too long'
*/

TPM_RESULT TSS_MGF1(unsigned char       *mask,
                    uint32_t            maskLen,
                    const unsigned char *mgfSeed,
                    uint32_t            mgfSeedlen)
{
    TPM_RESULT 		rc = 0;
    unsigned char       counter[4];     /* 4 octets */
    unsigned long       count;          /* counter as an integral type */
    unsigned long       outLen;
    TPM_DIGEST          lastDigest;     
    
    if (rc == 0) {
        /* this is possible with arrayLen on a 64 bit architecture, comment to quiet beam */
        if ((maskLen / TPM_DIGEST_SIZE) > 0xffffffff) {        /*constant condition*/
            printf(" TSS_MGF1: Error (fatal), Output length too large for 32 bit counter\n");
            rc = TPM_FAIL;              /* should never occur */
        }
    }
    /* 1.If l > 2^32(hLen), output "mask too long" and stop. */
    /* NOTE Checked by caller */
    /* 2. Let T be the empty octet string. */
    /* 3. For counter from 0 to [masklen/hLen] - 1, do the following: */
    for (count = 0, outLen = 0 ; (rc == 0) && (outLen < (unsigned long)maskLen) ; count++) {
        uint32_t count_n = htonl(count);
	/* a. Convert counter to an octet string C of length 4 octets - see Section 4.1 */
	/* C = I2OSP(counter, 4) NOTE Basically big endian */
	memcpy(&counter[0], &count_n, 4);
	/* b.Concatenate the hash of the seed mgfSeed and C to the octet string T: */
	/* T = T || Hash (mgfSeed || C) */
	/* If the entire digest is needed for the mask */
	if ((outLen + TPM_DIGEST_SIZE) < (unsigned long)maskLen) {
	    rc = TSS_SHA1(mask + outLen,
			  mgfSeedlen, mgfSeed,
			  4, counter,
			  0, NULL);
	    outLen += TPM_DIGEST_SIZE;
	}
	/* if the mask is not modulo TPM_DIGEST_SIZE, only part of the final digest is needed */
	else {
	    /* hash to a temporary digest variable */
	    rc = TSS_SHA1(lastDigest,
			  mgfSeedlen, mgfSeed,
			  4, counter,
			  0, NULL);
	    /* copy what's needed */
	    memcpy(mask + outLen, lastDigest, maskLen - outLen);
	    outLen = maskLen;           /* outLen = outLen + maskLen - outLen */
	}
    }
    /* 4.Output the leading l octets of T as the octet string mask. */
    return rc;
}

/* TSS_SHA1() can be called directly to hash a list of streams.

   The ... arguments to be hashed are a list of the form
   size_t length, unsigned char *buffer
   terminated by a 0 length
*/

TPM_RESULT TSS_SHA1(TPM_DIGEST md, ...)
{
    TPM_RESULT	rc = 0;
    va_list	ap;

    va_start(ap, md);
    rc = TPMC_SHA1_valist(md, 0, NULL, ap);
    va_end(ap);
    return rc;
}

/* SHA1_valist() is the internal function, called with the va_list already created.

   It is called from TSS_SHA1() to do a simple hash.  Typically length0==0 and buffer0==NULL.

   It can also be called from the HMAC function to hash the variable number of input parameters.  In
   that case, the va_list for the text is already formed.  length0 and buffer0 are used to input the
   padded key.
*/

static TPM_RESULT TPMC_SHA1_valist(TPM_DIGEST md,
                                  uint32_t length0, unsigned char *buffer0,
                                  va_list ap)
{
    TPM_RESULT		rc = 0;
    TPM_RESULT		rc1 = 0;
    uint32_t		length;
    unsigned char	*buffer;
    void		*context = NULL;	/* platform dependent context */
    TPM_BOOL		done = FALSE;
    
    if (rc == 0) {
	rc = TPMC_SHA1Init(&context);
    }
    if (rc == 0) {	
	if (length0 !=0) {		/* optional first text block */
	    rc = TPMC_SHA1_Update(context, buffer0, length0);	/* hash the buffer */
	}
    }
    while ((rc == 0) && !done) {
	length = va_arg(ap, uint32_t);			/* first vararg is the length */
	if (length != 0) {			/* loop until a zero length argument terminates */
	    buffer = va_arg(ap, unsigned char *);	/* second vararg is the array */
	    rc = TPMC_SHA1_Update(context, buffer, length);	/* hash the buffer */
	}
	else {
	    done = TRUE;
	}
    }
    if (rc == 0) {
	rc = TPMC_SHA1Final(md, context);
    }
    if (rc == 0) {
    }	 
    /* previous errors have priority, but call Delete even if there was an error */
    rc1 = TPMC_SHA1Delete(&context);
    if (rc == 0) {	/* if no processing error */
	rc = rc1;	/* report Delete error */
    }
    return rc;
}

/* for the openSSL version, TPM_SHA1Context is a SHA_CTX structure */

/* TPM_SHA1Init() initializes a platform dependent TPM_SHA1Context structure.

   The structure must be freed using TPM_SHA1Final()
*/

static TPM_RESULT TPMC_SHA1Init(void **context)
{
    TPM_RESULT  rc = 0;

    if (rc== 0) {
	*context = malloc(sizeof(SHA_CTX));
	if (*context == NULL) {
	    rc = ERR_MEM_ERR;
	}
    }
    if (rc== 0) {
        SHA1_Init(*context);
    }
    return rc;
}


static TPM_RESULT TPMC_SHA1_Update(void *context, const unsigned char *data, uint32_t length)
{
    TPM_RESULT  rc = 0;
    
    if (context != NULL) {
        SHA1_Update(context, data, length);
    }
    else {
        rc = TPM_SHA_THREAD;
    }
    return rc;
}


static TPM_RESULT TPMC_SHA1Final(unsigned char *md, void *context)
{
    TPM_RESULT  rc = 0;
    
    if (context != NULL) {
        SHA1_Final(md, context);
    }
    else {
        rc = TPM_SHA_THREAD;
    }
    return rc;
}

static TPM_RESULT TPMC_SHA1Delete(void **context)
{
    if (*context != NULL) {
        free(*context);
        *context = NULL;
    }
    return 0;
}

