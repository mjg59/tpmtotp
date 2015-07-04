CFLAGS = -ggdb -Wall -w -I.

LIBRARIES = libtpm.a
HEADERS = tpmfunc.h tpm.h tpmkeys.h
SOURCES = bind.c hmac.c keys.c migrate.c miscfunc.c oiaposap.c owner.c pcrs.c seal.c signature.c tpmutil.c chgauth.c
OBJECTS = bind.o hmac.o keys.o migrate.o miscfunc.o oiaposap.o owner.o pcrs.o seal.o signature.o tpmutil.o chgauth.o
EXTRA_DIST = hmac.h oiaposap.h pcrs.h tpmutil.h ./linux

libtpm.a: $(OBJECTS)
	ar -rcs libtpm.a $(OBJECTS)

clean:
	rm -f *.o libtpm.a
