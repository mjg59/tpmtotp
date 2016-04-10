CFLAGS = -ggdb -Wall -w -I. -DTPM_POSIX=1 -DTPM_NV_DISK=1 -DTPM_AES=1 -DTPM_V12=1 -DTPM_USE_TAG_IN_STRUCTURE=1 -DTPM_USE_CHARDEV=1

LIBRARIES = libtpm.a
HEADERS = tpmfunc.h tpm.h tpmkeys.h
SOURCES = auditing.c bind.c chgauth.c context.c \
        counter.c daa.c debug.c delegation.c dir.c \
        eviction.c hmac.c identity.c keys.c keyswap.c \
        maintenance.c management.c migrate.c miscfunc.c nv.c \
        oiaposap.c optin.c owner.c ownertpmdiag.c \
        pcrs.c raw.c rng.c seal.c serialize.c session.c \
        sha.c signature.c startup.c testing.c \
        ticks.c tpmutil.c tpmutil_sock.c tpmutil_tty.c tpmutil_unixio.c \
        tpmutil_libtpms.c \
        transport.c
OBJECTS = auditing.o bind.o chgauth.o context.o \
        counter.o daa.o debug.o delegation.o dir.o \
        eviction.o hmac.o identity.o keys.o keyswap.o \
        maintenance.o management.o migrate.o miscfunc.o nv.o \
        oiaposap.o optin.o owner.o ownertpmdiag.o \
        pcrs.o raw.o rng.o seal.o serialize.o session.o \
        sha.o signature.o startup.o testing.o \
        ticks.o tpmutil.o tpmutil_sock.o tpmutil_tty.o tpmutil_unixio.o \
        tpmutil_libtpms.o \
        transport.o
EXTRA_DIST = hmac.h oiaposap.h pcrs.h tpmutil.h

libtpm.a: $(OBJECTS)
	ar -rcs libtpm.a $(OBJECTS)

clean:
	rm -f *.o libtpm.a
