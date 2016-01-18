#!/bin/bash

check() {
    require_binaries unsealtotp
    if [ ! -f /etc/tpmtotp ]; then
	return 1;
    fi
}

depends() {
    echo plymouth
}

install() {
    inst_simple /usr/bin/unsealtotp
    inst_simple /etc/tpmtotp
    inst_simple "${systemdsystemunitdir}/tpmtotp.service"
    instmods tpm_tis
    mkdir -p "${initdir}${systemdsystemconfdir}/sysinit.target.wants"
    ln_r "${systemdsystemunitdir}/tpmtotp.service" "${systemdsystemconfdir}/sysinit.target.wants/"
}
