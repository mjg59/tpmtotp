#!/bin/bash

check() {
    require_binaries unsealtotp
    if [ ! -f /etc/tpmtotp ] && [ ! -f /sys/firmware/efi/efivars/TPMTOTP-6d6a372e-bd74-4ede-975d-df44eccf8226 ]; then
	return 1;
    fi
}

depends() {
    echo plymouth
}

install() {
    inst_simple /usr/bin/plymouth-unsealtotp
    if [ -f /etc/tpmtotp ]; then
	inst_simple /etc/tpmtotp
    fi
    inst_simple "/etc/adjtime"
    inst_simple "/etc/localtime"
    inst_simple "${systemdsystemunitdir}/tpmtotp.service"
    inst_libdir_file "plymouth/label.so"
    inst_simple "/usr/share/fonts/dejavu/DejaVuSans.ttf"
    instmods tpm_tis
    mkdir -p "${initdir}${systemdsystemconfdir}/sysinit.target.wants"
    ln_r "${systemdsystemunitdir}/tpmtotp.service" "${systemdsystemconfdir}/sysinit.target.wants/"
}
