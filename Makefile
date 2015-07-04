CFLAGS = -ggdb -w -Ilibtpm -std=c99

LDLIBS=-Llibtpm -ltpm -lcrypto -loath -lqrencode

APPS=sealtotp unsealtotp

all: libtpm/libtpm.a $(APPS)

libtpm/libtpm.a:
	$(MAKE) -C libtpm

sealtotp: sealtotp.o base32.o

unsealtotp: unsealtotp.o

clean:
	rm -f *.o $(APPS)
	$(MAKE) -C libtpm clean
