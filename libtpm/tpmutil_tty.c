/********************************************************************************/
/*										*/
/*			     	TPM Utility Functions				*/
/*			     Written by S. Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: tpmutil_tty.c 4702 2013-01-03 21:26:29Z kgoldman $		*/
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


/* These are platform specific.  This version uses a character device interface.

*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>

#include <unistd.h>     

#ifdef TPM_POSIX
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netdb.h>
#endif
#ifdef TPM_WINDOWS
#include <winsock2.h>
#endif
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#ifdef USE_SERIAL_PORT
#include <termios.h>
#endif

#include <openssl/rand.h>
#include <openssl/sha.h>

#include "tpm.h"
#include "tpmfunc.h"
#include "tpm_types.h"
#include "tpm_constants.h"
#include "tpmutil.h"
#include "tpm_lowlevel.h"

/* local prototypes */
static uint32_t TPM_OpenClientCharDev(int *sock_fd);
static uint32_t TPM_CloseClientCharDev(int sock_fd);
static uint32_t TPM_ReceiveCharDev(int sock_fd, struct tpm_buffer *tb);
static uint32_t TPM_TransmitCharDev(int sock_fd, struct tpm_buffer *tb,
                                    const char *mgs);
#ifdef USE_PARTIAL_READ
static uint32_t TPM_ReceiveBytes(int sock_fd,
                                 unsigned char *buffer,
                                 size_t nbytes);
#endif
#ifdef USE_SERIAL_PORT
   static struct termios saved_terminos;
   static enum { RAW, RESET } tty_state = RESET;

   static uint32_t set_tty(int fd) ;
   static uint32_t reset_tty(int fd) ;
#endif
/* local variables */
#define DEFAULT_TPM_DEVICE "/dev/tpm0"
#define VTPM_SOCKET "/var/vtpm/vtpm.socket"

static struct tpm_transport char_transport = {
    .open = TPM_OpenClientCharDev,
    .close = TPM_CloseClientCharDev,
    .send = TPM_TransmitCharDev,
    .recv  = TPM_ReceiveCharDev,
};

void TPM_LowLevel_TransportCharDev_Set(void)
{
    TPM_LowLevel_Transport_Set(&char_transport);
}


/****************************************************************************/
/*                                                                          */
/* Open the socket to the TPM Host emulation                                */
/*                                                                          */
/****************************************************************************/

static uint32_t 
TPM_OpenClientSocket_UnixIO(int *sock_fd)
{
    struct stat         _stat;
    if (0 == stat(VTPM_SOCKET, &_stat)) {
        if (S_ISSOCK(_stat.st_mode)) {
            *sock_fd = socket(PF_UNIX, SOCK_STREAM, 0);
            if (*sock_fd > 0) {
                struct sockaddr_un addr;
                addr.sun_family = AF_UNIX;
                strcpy(addr.sun_path, VTPM_SOCKET);
                if (connect(*sock_fd,
                            (struct sockaddr *)&addr,
                            sizeof(addr)) == 0) {
                    return 0;
                } else {
                    close(*sock_fd);
                    *sock_fd = 0;
                }
            }
        }
    }
    return ERR_IO;
}

static uint32_t TPM_OpenClientCharDev(int *sock_fd)
{
    char *tty_str;
    uint32_t rc;

    tty_str = getenv("TPM_DEVICE");

    if (tty_str == NULL || !strcmp("unixio",tty_str)) {
        rc = TPM_OpenClientSocket_UnixIO(sock_fd);
        if (rc == 0) {
            return 0;
        }
    }

    if (tty_str == NULL) {
        tty_str = DEFAULT_TPM_DEVICE;
    }

#ifndef USE_SERIAL_PORT
    if ((*sock_fd = open(tty_str,O_RDWR)) < 0) {
	printf("TPM_OpenClientCharDev: Could not open char device %s: %s\n",
	       tty_str,
	       strerror(errno));
	return ERR_IO;
    }
#else
    if ((*sock_fd = open(tty_str,O_RDWR | O_NOCTTY | O_NDELAY)) < 0) {
	printf("TPM_OpenClientCharDev: Could not open char device %s: %s\n",
	       tty_str,
	       strerror(errno));
	return ERR_IO;
    }
    fcntl(*sock_fd, F_SETFL, 0);

    if ((rc = set_tty(*sock_fd)) > 0) {
	close(*sock_fd);
	return rc;
    }
   
#endif
    return 0;
}
#ifdef USE_SERIAL_PORT
/* set tty to input and output raw mode and disable software flow control */
static uint32_t set_tty(int fd) {
   struct termios new_terminos;

   if (tcgetattr(fd, &saved_terminos) <  0) {
	printf("set_tty: Could not get tty termios info\n");
	return 1;
   }

   new_terminos = saved_terminos;
   /* enable */
   new_terminos.c_cflag |= (CREAD| CLOCAL | CS8); 

   /* set input to raw mode */
   new_terminos.c_lflag &= ~(ICANON | ECHO | ECHOE | ISIG);

   /* disable input processing */
   new_terminos.c_iflag &= ~(PARMRK | ISTRIP | IGNCR);

   /* disable software flow control */
   new_terminos.c_iflag &= ~(INLCR | ICRNL | IXON | IXOFF | IXANY);

   /* set output to raw mode */
   new_terminos.c_oflag &= ~(OPOST);

   /* set to read one byte at a time, no timer */
   new_terminos.c_cc[VMIN] = 1;
   new_terminos.c_cc[VTIME] = 0;

   if (tcsetattr(fd, TCSAFLUSH, &new_terminos) <  0) {
	printf("set_tty: Could not set tty termios info\n");
	return 1;
   }
   tty_state = RAW;
   return 0; 
}
/* retset tty */
static uint32_t reset_tty(int fd) {
  
   if (tty_state != RAW) {
	return 0;
   }
   if (tcsetattr(fd, TCSAFLUSH, &saved_terminos) <  0) {
	printf("reset_tty: Could not reset tty termios info\n");
	return 1;
   }
   tty_state = RESET;
   return 0;
}
#endif
/****************************************************************************/
/*                                                                          */
/* Close the socket to the TPM Host emulation                               */
/*                                                                          */
/****************************************************************************/

static uint32_t TPM_CloseClientCharDev(int sock_fd)
{

#ifdef USE_SERIAL_PORT
    reset_tty(sock_fd);
#endif
    close(sock_fd);
    return 0;
}

/* write buffer to socket sock_fd */

static uint32_t TPM_TransmitCharDev(int sock_fd, struct tpm_buffer *tb,
                                    const char *msg)
{
    uint32_t nbytes = 0;
    ssize_t nwritten = 0;
    size_t nleft = 0;
    unsigned int offset = 0;
    uint32_t ret;
    char mymsg[1024];
    
    snprintf(mymsg, sizeof(mymsg), "TPM_TransmitCharDev: To TPM [%s]",
             msg);

    ret = tpm_buffer_load32(tb, TPM_PARAMSIZE_OFFSET, &nbytes);
    if ((ret & ERR_MASK)) {
        return ret;
    }
    showBuff(tb->buffer, mymsg);

    nleft = nbytes;
    while (nleft > 0) {
	nwritten = write(sock_fd, &tb->buffer[offset], nleft);
	if (nwritten < 0) {        /* error */
	    printf("TPM_TransmitCharDev: write error %d\n", (int)nwritten);
	    return nwritten;
	}
	nleft -= nwritten;
	offset += nwritten;
    }
    return 0;
}

/* read a TPM packet from socket sock_fd */

static uint32_t
TPM_ReceiveCharDev(int sock_fd, struct tpm_buffer *tb)
{
    uint32_t rc = 0;
    uint32_t paramSize = 0;
    unsigned char *buffer = tb->buffer;

#ifndef USE_PARTIAL_READ
    /* read the whole packet */
    if (rc == 0) {
        int nread;
        nread = read(sock_fd, tb->buffer, tb->size);
        if (nread < 0) {
            rc = ERR_IO;
        } else {
            tb->used = nread;
        }
    }
#endif

#ifdef USE_PARTIAL_READ
    /* read the tag and paramSize */
    if (rc == 0) {
	rc = TPM_ReceiveBytes(sock_fd, buffer, TPM_U16_SIZE + TPM_U32_SIZE);
    }
#endif
    /* extract the paramSize */
    if (rc == 0) {
	paramSize = LOAD32(buffer, TPM_PARAMSIZE_OFFSET);
	if (paramSize > TPM_MAX_BUFF_SIZE) {
	    printf("TPM_ReceiveCharDev: paramSize %u greater than %u\n",
		   paramSize, TPM_MAX_BUFF_SIZE);
	    rc = ERR_BAD_RESP;
	}
    }
#ifdef USE_PARTIAL_READ
    /* read the rest of the packet */
    if (rc == 0) {
	rc = TPM_ReceiveBytes(sock_fd,
			      buffer + TPM_U16_SIZE + TPM_U32_SIZE,
			      paramSize - (TPM_U16_SIZE + TPM_U32_SIZE));
    }
#endif
    /* read the TPM return code from the packet */
    if (rc == 0) {
	showBuff(buffer, "TPM_ReceiveCharDev: From TPM");
	tb->used = paramSize;
	tpm_buffer_load32(tb, TPM_RETURN_OFFSET, &rc);
    }
    return rc;
}

#ifdef USE_PARTIAL_READ
/* read nbytes from socket sock_fd and put them in buffer */
static
uint32_t TPM_ReceiveBytes(int sock_fd,
			  unsigned char *buffer,
			  size_t nbytes)
{
    int nread = 0;
    int nleft = 0;

    nleft = nbytes;
    while (nleft > 0) {
	nread = read(sock_fd, buffer, nleft);
	if (nread <= 0) {       /* error */
	    printf("TPM_ReceiveBytes: read error %d\n", nread);
	    return ERR_IO;
	}
	else if (nread == 0) {  /* EOF */
	    printf("TPM_ReceiveBytes: read EOF\n");
	    return ERR_IO;
	}
	nleft -= nread;
	buffer += nread;
    }
    return 0;
}
#endif
