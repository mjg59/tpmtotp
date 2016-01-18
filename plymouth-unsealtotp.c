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
#include <ply-boot-client.h>
#include <liboath/oath.h>
#include <time.h>

#define keylen 20
char key[keylen];

static ply_boot_client_t *ply_client;
static ply_event_loop_t *ply_loop;

static void on_failure(void* dummy)
{
	ply_event_loop_exit(ply_loop, 0);
}

static void on_disconnect(void* dummy)
{
	ply_event_loop_exit(ply_loop, 0);
}

static void display_totp() {
	int ret;
	char totp[7];

	ret = oath_totp_generate(key, keylen, time(NULL), 30, 0, 6, totp);
	if (ret != 0) {
		fprintf(stderr, "Error generating totp value\n");
		exit(-1);
	}
	ply_boot_client_tell_daemon_to_display_message (ply_client,
							totp, NULL,
							(ply_boot_client_response_handler_t) on_failure, NULL);
}

static void on_timeout(void* dummy)
{
	time_t t = time(NULL);
	time_t delay;

	display_totp();
	delay = 30 - (t % 30);
	ply_event_loop_watch_for_timeout(ply_loop, delay, on_timeout, NULL);
}

int main(int argc, char *argv[])
{
	int ret;
	struct stat sbuf;	
	uint32_t parhandle;	/* handle of parent key */
	unsigned char blob[4096];	/* resulting sealed blob */
	unsigned int bloblen;	/* blob length */
	unsigned char passptr1[20] = {0};
	int fd, outlen;
	time_t t, delay;

	parhandle = 0x40000000;

	fd = open(argv[1], O_RDONLY);
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

	ply_client = ply_boot_client_new();
	ply_loop = ply_event_loop_new();
	if (!ply_boot_client_connect (ply_client, (ply_boot_client_disconnect_handler_t) on_disconnect, NULL)) {
		fprintf(stderr, "Plymouth not running\n");
		return -1;
	}
	ply_boot_client_attach_to_event_loop(ply_client, ply_loop);
	display_totp();

	t = time(NULL);
	delay = 30 - (t % 30);
	ply_event_loop_watch_for_timeout(ply_loop, delay, on_timeout, NULL);

	ply_event_loop_run(ply_loop);
	return 0;
}
