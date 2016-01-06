CFLAGS = -ggdb -w -Ilibtpm -std=c99 -Wall -Wextra -Werror

LDLIBS=-Llibtpm -ltpm -lcrypto -loath

APPS=sealtotp unsealtotp

all: libtpm/libtpm.a $(APPS)

libtpm/libtpm.a:
	$(MAKE) -C libtpm

unsealtotp: unsealtotp.o

LDLIBS+=-ltspi -lqrencode

sealtotp: sealtotp.o base32.o

clean:
	rm -f *.o $(APPS)
	$(MAKE) -C libtpm clean
