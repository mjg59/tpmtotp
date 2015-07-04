/*
 * libtpm: tpm utility routines
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
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <netinet/in.h>
#include <tpm.h>
#include <tpmutil.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <sys/ioctl.h>
#include "linux/tpm.h"

static unsigned int logflag = 0;

/*#define DEBUG 1*/

/****************************************************************************/
/*                                                                          */
/* Get the Size in a returned response                                      */
/*                                                                          */
/****************************************************************************/
uint32_t TSS_getsize(unsigned char *rsp)
{
	uint32_t size;

	size = LOAD32(rsp, TPM_PARAMSIZE_OFFSET);
	return size;
}

int TSS_gennonce(unsigned char *buf)
{
        return((int)TPM_GetRandom(buf));
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
/*     in the format string as hex ascii.  These MUST be in pairs,          */
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
uint32_t TSS_buildbuff(char *format, unsigned char *buffer, ...)
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
	unsigned char byte;
	unsigned char hexflag;
	unsigned char *ptr;
	int i;

	va_start(argp, buffer);
	i = 0;
	o = buffer;
	totpos = 0;
	totlen = 0;
	hexflag = 0;
	p = format;
	while (*p != '\0') {
		switch (*p) {
		case ' ':
			break;
		case 'L':
			if (hexflag)
				return ERR_BAD_ARG;
			byte = 0;
			l = (unsigned long) va_arg(argp, unsigned long);
			STORE32(o, 0, l);
			o += TPM_U32_SIZE;
			totlen += TPM_U32_SIZE;
			break;
		case 'S':
			if (hexflag)
				return ERR_BAD_ARG;
			byte = 0;
			s = (unsigned short) va_arg(argp, int);
			STORE16(o, 0, s);
			o += TPM_U16_SIZE;
			totlen += TPM_U16_SIZE;
			break;
		case 'l':
			if (hexflag)
				return ERR_BAD_ARG;
			byte = 0;
			l = (unsigned long) va_arg(argp, unsigned long);
			STORE32N(o, 0, l);
			o += TPM_U32_SIZE;
			totlen += TPM_U32_SIZE;
			break;
		case 's':
			if (hexflag)
				return ERR_BAD_ARG;
			byte = 0;
			s = (unsigned short) va_arg(argp, int);
			STORE16N(o, 0, s);
			o += TPM_U16_SIZE;
			totlen += TPM_U16_SIZE;
			break;
		case 'o':
			if (hexflag)
				return ERR_BAD_ARG;
			byte = 0;
			c = (unsigned char) va_arg(argp, int);
			*(o) = c;
			o += 1;
			totlen += 1;
			break;
		case '@':
			if (hexflag)
				return ERR_BAD_ARG;
			byte = 0;
			len = (int) va_arg(argp, int);
			ptr =
			    (unsigned char *) va_arg(argp,
						     unsigned char *);
			if (len > 0 && ptr == NULL)
				return -3;
			STORE32(o, 0, len);
			o += TPM_U32_SIZE;
			if (len > 0)
				memcpy(o, ptr, len);
			o += len;
			totlen += len + TPM_U32_SIZE;
			break;
		case '%':
			if (hexflag)
				return ERR_BAD_ARG;
			byte = 0;
			len = (int) va_arg(argp, int);
			ptr =
			    (unsigned char *) va_arg(argp,
						     unsigned char *);
			if (len > 0 && ptr == NULL)
				return ERR_NULL_ARG;
			if (len > 0)
				memcpy(o, ptr, len);
			o += len;
			totlen += len;
			break;
		case 'T':
			if (hexflag)
				return ERR_BAD_ARG;
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
			byte = byte << 4;
			byte = byte | ((*p - '0') & 0x0F);
			if (hexflag) {
				*o = byte;
				++o;
				hexflag = 0;
				totlen += 1;
			} else
				++hexflag;
			break;
		case 'A':
		case 'B':
		case 'C':
		case 'D':
		case 'E':
		case 'F':
			byte = byte << 4;
			byte = byte | (((*p - 'A') & 0x0F) + 0x0A);
			if (hexflag) {
				*o = byte;
				++o;
				hexflag = 0;
				totlen += 1;
			} else
				++hexflag;
			break;
		case 'a':
		case 'b':
		case 'c':
		case 'd':
		case 'e':
		case 'f':
			byte = byte << 4;
			byte = byte | (((*p - 'a') & 0x0F) + 0x0A);
			if (hexflag) {
				*o = byte;
				++o;
				hexflag = 0;
				totlen += 1;
			} else
				++hexflag;
			break;
		default:
			return ERR_BAD_ARG;
		}
		++p;
	}
	if (totpos != 0)
		STORE32(totpos, 0, totlen);
	va_end(argp);
#ifdef DEBUG
	fprintf(stderr, "buildbuff results...\n");
	for (i = 0; i < totlen; i++) {
		if (i && !(i % 16)) {
			fprintf(stderr, "\n");
		}
		fprintf(stderr, "%.2X ", buffer[i]);
	}
	fprintf(stderr, "\n");
#endif
	return totlen;
}

/****************************************************************************/
/*                                                                          */
/*  optional verbose logging of data to/from tpm chip                       */
/*                                                                          */
/****************************************************************************/
static void showBuff(unsigned char *buff, char *string)
{
	uint32_t i, len;

	if (!logflag)
		return;
	len = LOAD32(buff, TPM_PARAMSIZE_OFFSET);
	fprintf(stderr, "%s length=%d\n", string, len);
	for (i = 0; i < len; i++) {
		if (i && !(i % 16)) {
			fprintf(stderr, "\n");
		}
		fprintf(stderr, "%.2X ", buff[i]);
	}
	fprintf(stderr, "\n");
}

/****************************************************************************/
/*                                                                          */
/* Transmit request to TPM and read Response                                */
/*                                                                          */
/****************************************************************************/
uint32_t TPM_Transmit(unsigned char *buff, char *msg)
{
	int tpmfp;
	int len;
	uint32_t size;
	uint32_t ret;

	if ((tpmfp = open("/dev/tpm0", O_RDWR)) < 0) {
		return ERR_IO;
	}
	size = LOAD32(buff, TPM_PARAMSIZE_OFFSET);
	showBuff(buff, "To TPM");
	len = write(tpmfp, buff, size);
	if (len > 0) {
		len = read(tpmfp, buff, TPM_MAX_BUFF_SIZE);
		close(tpmfp);
	} else if (errno == EINVAL) {
		len = ioctl(tpmfp, TPMIOC_TRANSMIT, buff);
		close(tpmfp);
	} else
		return ERR_IO;
	if (len <= 0)
		return ERR_IO;
	if (logflag)
		showBuff(buff, "From TPM");
	ret = LOAD32(buff, TPM_RETURN_OFFSET);
	if (logflag) {
		if (ret)
			fprintf(stderr, "%s failed with error %d\n", msg,
				ret);
		else
			fprintf(stderr, "%s succeeded\n", msg);
	}
	return ret;
}

/****************************************************************************/
/*                                                                          */
/* Perform a SHA1 hash on a single buffer                                   */
/*                                                                          */
/****************************************************************************/
void TSS_sha1(unsigned char *input, int len, unsigned char *output)
{
	SHA_CTX sha;

	SHA1_Init(&sha);
	SHA1_Update(&sha, input, len);
	SHA1_Final(output, &sha);
}

/****************************************************************************/
/*                                                                          */
/* set logging flag                                                         */
/*                                                                          */
/****************************************************************************/
int TPM_setlog(int flag)
{
	int old;

	old = logflag;
	logflag = flag;
	return old;
}

static unsigned char getrandom[] = {
        0, 193,         /* TPM_TAG_RQU_COMMAND */
        0, 0, 0, 14,    /* length */
        0, 0, 0, 70,    /* TPM_ORD_GetRandom */
        0, 0, 0, 20,    /* requested bytes */
};

uint32_t TPM_GetRandom(unsigned char *buf)
{
        unsigned char data[2048];
        ssize_t len, err;

        memcpy(data, getrandom, sizeof(getrandom));
        if ((err = TPM_Transmit(data, "gennonce")) !=0){
                printf("gennonce returned %d\n",err);
                return 0;
        }
        if ((len = LOAD32(data,2)) != 34){
                printf("gennonce len %d\n",len);
                return -len;
        }
        len -= 14; /* skip header */
        memcpy(buf, data+14, len);
        return len;
}

