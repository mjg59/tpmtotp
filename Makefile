
CFLAGS = -ggdb -w -Ilibtpm -std=c99 -Wall -Wextra -Werror

PLYMOUTH_CFLAGS = `pkg-config --cflags ply-boot-client`

LDLIBS=-Llibtpm -ltpm -lcrypto -loath

PLYMOUTH_LDLIBS = `pkg-config --libs ply-boot-client`

APPS=sealtotp unsealtotp plymouth-unsealtotp

all: libtpm/libtpm.a $(APPS)

libtpm/libtpm.a:
	$(MAKE) -C libtpm

unsealtotp: unsealtotp.o

plymouth-unsealtotp: plymouth-unsealtotp.c
	$(CC) $(CFLAGS) $(PLYMOUTH_CFLAGS) -o $@ $< $(PLYMOUTH_LDLIBS) $(LDLIBS)

sealtotp: sealtotp.c base32.c
	$(CC) $(CFLAGS) -ltspi -lqrencode -o $@ $? $(LDLIBS)

clean:
	rm -f *.o $(APPS)
	$(MAKE) -C libtpm clean

install:
	install sealtotp unsealtotp plymouth-unsealtotp /usr/bin/
	install -D dracut/module-setup.sh /usr/lib/dracut/modules.d/60tpmtotp/module-setup.sh
	install -m 0644 tpmtotp.service /lib/systemd/system
	systemctl enable tpmtotp.service

uninstall:
	rm /usr/bin/sealtotp /usr/bin/unsealtotp /usr/bin/plymouth-unsealtotp
	rm -rf /usr/lib/dracut/modules.d/60tpmtotp/
	rm /lib/systemd/system/tpmtotp.service
