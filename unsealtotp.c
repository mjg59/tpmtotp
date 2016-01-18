/*
 * sealtotp - generate a TOTP secret and seal it to the local TPM
 *
 * Copyright 2015 Matthew Garrett <mjg59@srcf.ucam.org>
 *
 * Portions derived from unsealfile.c by J. Kravitz and Copyright (C) 2004 IBM
 * Corporation
 *
 */


#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <getopt.h>
#include "tpmfunc.h"
#include <liboath/oath.h>

#define keylen 20
char key[keylen];
const char efivarfs[] = "/sys/firmware/efi/efivars/";

int main(int argc, char *argv[])
{
	int ret;
	struct stat sbuf;	
	uint32_t parhandle;	/* handle of parent key */
	unsigned char blob[4096];	/* resulting sealed blob */
	unsigned int bloblen;	/* blob length */
	unsigned char passptr1[20] = {0};
	int fd, outlen, i;
	char totp[7];
	parhandle = 0x40000000;
	
	for (i=1; i<argc; i++) {
		fd = open(argv[1], O_RDONLY);
		if (fd < 0) {
			argv++;
		}
	}

	if (fd < 0) {
		perror("Unable to open file");
		return -1;
	}

	ret = fstat(fd, &sbuf);
	if (ret) {
		perror("Unable to stat file");
		return -1;
	}

	bloblen = sbuf.st_size;
	ret = read(fd, blob, bloblen);

	if (ret != bloblen) {
		fprintf(stderr, "Unable to read data\n");
		return -1;
	}

	if (strncmp(argv[1], efivarfs, strlen(efivarfs)) == 0) {
		bloblen -= sizeof(int);
		memmove (blob, blob + sizeof(int), bloblen);
	}

	ret = TPM_Unseal(parhandle,	/* KEY Entity Value */
			 passptr1,	/* Key Password */
			 NULL,
			 blob, bloblen,
			 key, &outlen);

	if (ret == 24) {
		fprintf(stderr, "TPM refused to decrypt key - boot process attests that it is modified\n");
		return -1;
	}

	if (ret != 0) {
		printf("Error %s from TPM_Unseal\n", TPM_GetErrMsg(ret));
		exit(6);
	}

	if (outlen != keylen) {
		fprintf(stderr, "Returned buffer is incorrect length\n");
		return -1;
	}

	ret = oath_totp_generate(key, keylen, time(NULL), 30, 0, 6, totp);
	if (ret != 0) {
		fprintf(stderr, "Error generating totp value\n");
		return -1;
	}
	printf("%s\n", totp);
}
