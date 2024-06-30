#!/bin/bash

cleanup() {
    rm -f /tmp/tdx-guest-*.log &> /dev/null
    rm -f /tmp/tdx-demo-*-monitor.sock &> /dev/null

    PID_TD=$(cat /tmp/tdx-demo-td-pid.pid 2> /dev/null)

    [ ! -z "$PID_TD" ] && echo "Cleanup, kill TD with PID: ${PID_TD}" && kill -TERM ${PID_TD} &> /dev/null
    sleep 3
}
TD_IMG=${TD_IMG:-${PWD}/image/tdx-guest-ubuntu-24.04-generic.qcow2}
TDVF_FIRMWARE=/usr/share/ovmf/OVMF.fd
FDE=false
OVMF=false
process_args() {
    echo "Inside process_args"
    while getopts ":hfo:" option; do
	echo "Option = $option"
        case "$option" in
            o) OVMF=$OPTARG;;
            f) FDE=true;;
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
    echo "FDE insdie = ${FDE}"
}

usage() {
    cat << EOM
Usage: $(basename "$0") [OPTION]...
  -o <OVMF file>            BIOS firmware device file, for "td"
  -f                        Enable FDE boot
  -h                        Show this help
EOM
}

cleanup
process_args "$@"

echo "FDE = $FDE"
echo "OVMF =$OVMF"

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
echo $TDVF_FIRMWARE
echo $CONSOLE
###################### RUN VM WITH TDX SUPPORT ##################################
SSH_PORT=10022
PROCESS_NAME=td
LOGFILE='/tmp/tdx-guest-td.log'
# approach 1 : talk to QGS directly
QUOTE_ARGS="-device vhost-vsock-pci,guest-cid=3"
qemu-system-x86_64 -D $LOGFILE \
		   -accel kvm \
		   -m 2G -smp 16 \
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
		   -pidfile /tmp/tdx-demo-td-pid.pid

ret=$?
if [ $ret -ne 0 ]; then
	echo "Error: Failed to create TD VM. Please check logfile \"$LOGFILE\" for more information."
	exit $ret
fi

PID_TD=$(cat /tmp/tdx-demo-td-pid.pid)

echo "TD, PID: ${PID_TD}, SSH : ssh -p 10022 root@localhost"
