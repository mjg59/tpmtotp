/*
 * sealtotp - generate a TOTP secret and seal it to the local TPM
 *
 * Copyright 2015 Matthew Garrett <mjg59@srcf.ucam.org>
 *
 * Portions derived from sealfile.c by J. Kravitz and Copyright (C) 2004 IBM
 * Corporation
 *
 * Portions derived from qrenc.c Copyright (C) 2006-2012 Kentaro Fukuchi
 * <kentaro@fukuchi.org>
 *
 *      This program is free software; you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License as published by
 *      the Free Software Foundation; either version 2 of the License, or
 *      (at your option) any later version.
 */

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <getopt.h>
#include <qrencode.h>
#include "tpmfunc.h"
#include "base32.h"

#define keylen 20
char key[keylen];
static int margin=1;

static void writeANSI_margin(FILE* fp, int realwidth,
			     char* buffer, int buffer_s,
			     char* white, int white_s )
{
	int y;

	strncpy(buffer, white, white_s);
	memset(buffer + white_s, ' ', realwidth * 2);
	strcpy(buffer + white_s + realwidth * 2, "\033[0m\n"); // reset to default colors
	for(y=0; y<margin; y++ ){
		fputs(buffer, fp);
	}
}

static int writeANSI(QRcode *qrcode)
{
	FILE *fp;
	unsigned char *row, *p;
	int x, y;
	int realwidth;
	int last, size;

	char *white, *black, *buffer;
	int white_s, black_s, buffer_s;

	white = "\033[47m";
	white_s = 5;
	black = "\033[40m";
	black_s = 5;

	size = 1;

	fp = stdout;

	realwidth = (qrcode->width + margin * 2) * size;
	buffer_s = ( realwidth * white_s ) * 2;
	buffer = (char *)malloc( buffer_s );
	if(buffer == NULL) {
		fprintf(stderr, "Failed to allocate memory.\n");
		exit(EXIT_FAILURE);
	}

	/* top margin */
	writeANSI_margin(fp, realwidth, buffer, buffer_s, white, white_s);

	/* data */
	p = qrcode->data;
	for(y=0; y<qrcode->width; y++) {
		row = (p+(y*qrcode->width));

		bzero( buffer, buffer_s );
		strncpy( buffer, white, white_s );
		for(x=0; x<margin; x++ ){
			strncat( buffer, "  ", 2 );
		}
		last = 0;

		for(x=0; x<qrcode->width; x++) {
			if(*(row+x)&0x1) {
				if( last != 1 ){
					strncat( buffer, black, black_s );
					last = 1;
				}
			} else {
				if( last != 0 ){
					strncat( buffer, white, white_s );
					last = 0;
				}
			}
			strncat( buffer, "  ", 2 );
		}

		if( last != 0 ){
			strncat( buffer, white, white_s );
		}
		for(x=0; x<margin; x++ ){
			strncat( buffer, "  ", 2 );
		}
		strncat( buffer, "\033[0m\n", 5 );
		fputs( buffer, fp );
	}

	/* bottom margin */
	writeANSI_margin(fp, realwidth, buffer, buffer_s, white, white_s);

	fclose(fp);
	free(buffer);

	return 0;
}

int generate_key() {
	int fd = open("/dev/urandom", O_RDONLY);
	int ret;
	if (fd < 0) {
		perror("Unable to open urandom");
		return -1;
	}
	ret = read(fd, key, sizeof(key));
	if (ret != 20) {
		fprintf(stderr, "Unable to read from urandom");
		return -1;
	}
	return 0;
}

int main(int argc, char *argv[])
{
	int ret;
	char base32_key[BASE32_LEN(keylen)+1];
	unsigned char blob[4096];	/* resulting sealed blob */
	unsigned int bloblen;	/* blob length */
	unsigned char wellknown[20] = {0};
	unsigned char totpstring[64];
	FILE *infile;
	FILE *outfile;
	QRcode *qrcode;
	int nxtarg;

	if (generate_key()) {
		return -1;
	}
	base32_encode(key, keylen, base32_key);
	base32_key[BASE32_LEN(keylen)] = NULL;
	ret = TPM_SealCurrPCR(0x40000000, // SRK
			      0x000000BF, // PCRs 0-5 and 7
			      wellknown,  // Well-known SRK secret
			      wellknown,  // Well-known SEAL secret
			      key, keylen,	/* data to be sealed */
			      blob, &bloblen);	/* buffer to receive result */
	if (ret != 0) {
		fprintf(stderr, "Error %s from TPM_Seal\n",
			TPM_GetErrMsg(ret));
		return -1;
	}

	sprintf(totpstring, "otpauth://totp/TPMTOTP?secret=%s", base32_key);
	qrcode = QRcode_encodeString(totpstring, 0, QR_ECLEVEL_L, QR_MODE_8, 1);
	writeANSI(qrcode);
	outfile = fopen(argv[1], "w");
	if (outfile == NULL) {
		fprintf(stderr, "Unable to open output file '%s'\n",
			argv[1]);
		return -1;
	}
	ret = fwrite(blob, 1, bloblen, outfile);
	if (ret != bloblen) {
		fprintf(stderr,
			"I/O Error while writing output file '%s'\n",
			argv[1]);
		return -1;
	}
	fclose(outfile);
	exit(0);
}
