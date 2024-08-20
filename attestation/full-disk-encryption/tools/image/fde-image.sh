#!/bin/bash

# Full Disk Encryption (FDE) image creation includes the following steps:
# - (Optional) Generate key and register key to KBS
# - (Optional) Enroll KBS information and key ID to OVMF variables
# - Create an image with EFI/Boot partitions
# - Create LUKS encrypted rootfs partition and extract ubuntu cloud image rootfs
# - Install TDX-related packages and setup environments
# - Clean up mount points and deactivate the LUKS partition

set -e

THIS_DIR=$(dirname "$(readlink -f "$0")")
export FDE_DIR=${THIS_DIR}/../../../full-disk-encryption

# Default rootfs is from ubuntu cloud image
ROOTFS_URL=https://cloud-images.ubuntu.com/noble/current/
ROOTFS_TAR=noble-server-cloudimg-amd64-root.tar.xz
# Size of rootfs partition and boot partition
ROOTFS_SIZE=10G
BOOT_SIZE=2G
# TDX package repo
TDX_REPO_URL=""
ROOT_PASS="123456"
OUTPUT_IMAGE=td-guest-ubuntu-24.04-encrypted.img

# key & key_id
KEY=""
KEY_ID=""
URL=""
FIRST_BOOT=2

usage() {
    cat << EOF
Usage: $(basename "$0") [OPTION]...
 [Required]
  -k <disk encryption key>          Key for encryptin disk
  -u <kbs url>                      kbs url with transfer link
  -i <disk encryption key_id>       The key_id binding with key
 [Optional]
  -r <rootfs partition size>        Rootfs partition size, default is 10G
  -b <boot partition size>          Boot partition size, default is 2G
  -o <output image name>            Default is td-guest-ubuntu-23.10-encrypted.img
  -p <guest root password>          Default is 123456, recommend changing it
  -h                                Show this help
EOF
}

process_args() {
    while getopts "h:r:b:o:p:k:s:l:v:i:u:f:" option; do
        case "$option" in
            r) ROOTFS_SIZE=$OPTARG;;
            b) BOOT_SIZE=$OPTARG;;
            o) OUTPUT_IMAGE=$OPTARG;;
            p) ROOT_PASS=$OPTARG;;
            k) KEY=$OPTARG;;
            i) KEY_ID=$OPTARG;;
	    u) URL=$OPTARG;;
	    f) FIRST_BOOT=$OPTARG;;
            h) usage
               exit 0
               ;;
            *)
               echo "Invalid option '-$OPTARG'"
               usage
               exit 1
               ;;
        esac
    done
}

error() {
    echo -e "\e[1;31mERROR: $*\e[0;0m"
    exit 1
}

check_args_env() {
    # Provide a 256 bit (32 bytes) key and key_id
    if [[ -z ${KEY} || -z ${KEY_ID} ]]; then
        error "key and key_id are required, please provide by '-k' and '-i' ."
        # shellcheck disable=SC2317
        exit 1
    fi

    # Check and install packages needed
    PACKAGES=""
    if [[ -z "$(command -v jq)" ]]; then
        PACKAGES+="jq "
    fi

    if [[ -z "$(command -v openssl)" ]]; then
        PACKAGES+="openssl "
    fi

    if [[ -n $PACKAGES ]]; then
        apt install -y "$PACKAGES"
    fi
    if [ $(dpkg-query -W -f='${Status}' python3-venv 2>/dev/null | grep -c "ok installed") -eq 0 ];
    then
       apt-get install python3-venv;
    fi
    if [ -e /tmp/ovmf_install/bin/activate ]; then
	echo "Found python virtaul env folder! using it"
	source /tmp/ovmf_install/bin/activate
    	if [[ -z "$(command -v ovmfkeyenroll)" ]]; then
           python3 -m pip install ovmfkeyenroll
	   deactivate
	fi
    else
	python3 -m venv /tmp/ovmf_install
	source /tmp/ovmf_install/bin/activate
        python3 -m pip install ovmfkeyenroll
	deactivate
    fi
}
modify_ovmf() {
    source /tmp/ovmf_install/bin/activate
    #need below steps until solving the OVMF key enrollment issue in ovmf noble package.
    cd /tmp
    mkdir -p prep_ovmf
    cd prep_ovmf
    wget http://launchpadlibrarian.net/688822449/ovmf_2023.05-2_all.deb
    ar -x ovmf_2023.05-2_all.deb
    tar -xf data.tar.zst
    cp usr/share/ovmf/OVMF.fd $FDE_DIR/tools/image
    cd /tmp
    rm -rf prep_ovmf
    cd $FDE_DIR/tools/image
    URL=$URL$KEY_ID
    #cp /usr/share/qemu/OVMF.fd $FDE_DIR/tools/image
    printf $URL>$FDE_DIR/tools/image/url.txt
    NAME="KBSURL"
    GUID="0d9b4a60-e0bf-4a66-b9b1-db1b98f87770"
    DATA="url.txt"
    python3 $FDE_DIR/tools/image/enroll_vars.py -i OVMF.fd -o OVMF_FDE.fd -n $NAME -g $GUID -d $DATA
    cp /etc/kbs/certs/tls/tls.crt $FDE_DIR/tools/image/cert.cer
    NAME="KBSCert"
    GUID="d2bf05a0-f7f8-41b6-b0ff-ad1a31c34d37"
    DATA="cert.cer"
    python3 $FDE_DIR/tools/image/enroll_vars.py -i OVMF_FDE.fd -o OVMF_FDE.fd -n $NAME -g $GUID -d $DATA
    JSON_UserData='{"keyid":"%s"}\n'
    printf "$JSON_UserData" "$KEY_ID">userdata.txt
    NAME="KBSUserData"
    GUID="732284dd-70c4-472a-aa45-1ffda02caf74"
    DATA="userdata.txt"
    python3 $FDE_DIR/tools/image/enroll_vars.py -i OVMF_FDE.fd -o OVMF_FDE.fd -n $NAME -g $GUID -d $DATA
    deactivate
}





create_image() {
    # Caculate image size, reserve 101M for EFI and BIOS boot
    IMAGE_SIZE=$(echo "($ROOTFS_SIZE+$BOOT_SIZE+101M)" | \
    sed -e 's/K/\*1024/g' -e 's/M/\*1048576/g' -e 's/G/\*1073741824/g' | bc)

    # Create sparse file to represent output disk
    truncate --size "$IMAGE_SIZE" "$OUTPUT_IMAGE"
}

echo "=============== Building Starting ==============="

process_args "$@"

check_args_env

# Create an empty image
create_image

echo "=============== Empty Image Inited ==============="

# Setup partitions
# shellcheck disable=SC1091
. scripts/partition
create_partitions "$BOOT_SIZE" "$OUTPUT_IMAGE"
echo "Partitions done"

echo "=============== Image Partition Created =========="

create_luks_partition "$KEY"

echo "=============== Root Encrypted & Opened =========="

format_partitions "$EFI" "$BOOT" "$ROOT_ENC"
echo "Formating done"

echo "=============== Image Partition Formatted ========"

# Make rootfs
echo "Calling make rootfs"
make_rootfs "$ROOTFS_URL" "$ROOTFS_TAR"  "$EFI" "$BOOT" "$ROOT_ENC" "$ROOT" "$ROOT_PASS" "$FIRST_BOOT"

echo "=============== Image Rootfs Created ============="

# Deactivate partitions
close_partitions "$LOOPDEV"
modify_ovmf
echo "=============== Building Finished ================"
