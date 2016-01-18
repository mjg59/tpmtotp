
CFLAGS = -ggdb -w -Ilibtpm -std=c99 -Wall -Wextra -Werror

PLYMOUTH_CFLAGS = `pkg-config --cflags ply-boot-client`

LDLIBS=-Llibtpm -ltpm -lcrypto -loath -lqrencode

PLYMOUTH_LDLIBS = `pkg-config --libs ply-boot-client`

APPS=sealtotp unsealtotp plymouth-unsealtotp

all: libtpm/libtpm.a $(APPS)

libtpm/libtpm.a:
	$(MAKE) -C libtpm

unsealtotp: unsealtotp.o

plymouth-unsealtotp: plymouth-unsealtotp.c
	$(CC) $(CFLAGS) $(PLYMOUTH_CFLAGS) -o $@ $< $(PLYMOUTH_LDLIBS) $(LDLIBS)

sealtotp: sealtotp.c base32.c
	$(CC) $(CFLAGS) -ltspi -o $@ $? $(LDLIBS)

clean:
	rm -f *.o $(APPS)
	$(MAKE) -C libtpm clean
