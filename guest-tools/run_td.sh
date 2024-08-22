#!/bin/bash

cleanup() {
    rm -f /tmp/tdx-guest-*.log &> /dev/null
    rm -f /tmp/tdx-demo-*-monitor.sock &> /dev/null

    PID_TD=$(cat /tmp/tdx-demo-td-pid.pid 2> /dev/null)

    [ ! -z "$PID_TD" ] && echo "Cleanup, kill TD with PID: ${PID_TD}" && kill -TERM ${PID_TD} &> /dev/null
    sleep 10
}
TD_IMG=${TD_IMG:-${PWD}/image/tdx-guest-ubuntu-24.04-generic.qcow2}
TDVF_FIRMWARE=/usr/share/ovmf/OVMF.fd
FDE=false
OVMF=false
DPT=false
process_args() {
    while getopts ":hdfo:" option; do
        case "$option" in
            o) OVMF=$OPTARG;;
            f) FDE=true;;
	    d) DPT=true;;
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

usage() {
    cat << EOM
Usage: $(basename "$0") [OPTION]...
  -o <OVMF file>            BIOS firmware device file, for "td"
  -f                        Enable FDE boot
  -d                        Device Passthrough
  -h                        Show this help
EOM
}

cleanup
process_args "$@"


if [ "$1" = "clean" ]; then
    exit 0
fi

if ! groups | grep -qw "kvm"; then
    echo "Please add user $USER to kvm group to run this script (usermod -aG kvm $USER and then log in again)."
    exit 1
fi
if [[ ${FDE} == true  && ${OVMF} == false ]]; then
	echo "Should specify OVMF for FDE"
	exit 0
fi
if [[ ${FDE} == true ]]; then 
    if [[ ! -f $OVMF ]]; then
        echo "Could not find $OVMF. Please specify the OVMF for FDE."
	exit 0
    fi
    TDVF_FIRMWARE=$OVMF
    CONSOLE="-chardev stdio,id=mux,mux=on  \
             -device virtio-serial,romfile= \
             -device virtconsole,chardev=mux -monitor chardev:mux \
             -serial chardev:mux "
else
    CONSOLE="-daemonize"
fi
if [[ ${DPT} == true ]]; then
    MEMORY=128
    DEVICE_PASS="-object iommufd,id=iommufd0 \
	        -device pcie-root-port,id=pci.1,bus=pcie.0 \
                -device vfio-pci,host=38:00.0,bus=pci.1,iommufd=iommufd0 -fw_cfg name=opt/ovmf/X-PciMmio64,string=262144 \
		-pidfile /tmp/tdx-demo-td-pid.pid"

else
   MEMORY=2
   DEVICE_PASS="-pidfile /tmp/tdx-demo-td-pid.pid"
fi
###################### RUN VM WITH TDX SUPPORT ##################################
SSH_PORT=10022
PROCESS_NAME=td
LOGFILE='/tmp/tdx-guest-td.log'
# approach 1 : talk to QGS directly
QUOTE_ARGS="-device vhost-vsock-pci,guest-cid=3"
/usr/bin/qemu-system-x86_64 -D $LOGFILE \
		   -accel kvm \
		   -m ${MEMORY}G -smp 16 \
		   -name ${PROCESS_NAME},process=${PROCESS_NAME},debug-threads=on \
		   -cpu host \
		   -object tdx-guest,id=tdx \
		   -machine q35,kernel_irqchip=split,confidential-guest-support=tdx,hpet=off \
		   -bios ${TDVF_FIRMWARE} \
		   -nographic \
		   -nodefaults  \
		   -device virtio-net-pci,netdev=nic0_td -netdev user,id=nic0_td,hostfwd=tcp::${SSH_PORT}-:22 \
		   -drive file=${TD_IMG},if=none,id=virtio-disk0 \
		   ${CONSOLE} \
		   -device virtio-blk-pci,drive=virtio-disk0 \
		   ${QUOTE_ARGS} \
		   ${DEVICE_PASS}

ret=$?
if [ $ret -ne 0 ]; then
	echo "Error: Failed to create TD VM. Please check logfile \"$LOGFILE\" for more information."
	exit $ret
fi

PID_TD=$(cat /tmp/tdx-demo-td-pid.pid)

echo "TD, PID: ${PID_TD}, SSH : ssh -p 10022 root@localhost"
