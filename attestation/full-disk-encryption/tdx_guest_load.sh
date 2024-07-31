#!/bin/bash

CUR_DIR=$(pwd)
TDX_DIR="$CUR_DIR"/../../guest-tools
GUEST_TOOLS_DIR=$TDX_DIR
TD_GUEST_PASSWORD=123456
TD_GUEST_PORT=10022
if [[ -z "$SUDO_USER" ]]; then
        LOGIN_USER=`whoami`
else
        LOGIN_USER=$SUDO_USER
fi
TD_IMAGE_PATH=$CUR_DIR/tools/image/td-guest-ubuntu-24.04-encrypted.img
OVMF_IMG_PATH=$CUR_DIR/tools/image/OVMF_FDE.fd


launch_td_guest() {
        echo -e "\nBoot TD guest ..."
        if [ ! -f $TD_IMAGE_PATH ]; then
                echo -e "\n\nERROR: TD guest image is not found at $TD_IMAGE_PATH"
                return 1
        fi
        if [ ! -f $OVMF_IMG_PATH ]; then
                echo -e "\n\nERROR: OVMF image is not found at $OVMF_IMG_PATH"
                return 1
        fi
        cd "$GUEST_TOOLS_DIR"
        TD_IMG=$TD_IMAGE_PATH ./run_td.sh -f -o $OVMF_IMG_PATH>/dev/null 2>&1 &
	sleep 120
	count=0
        echo -e "\nVerifying TDX enablement on guest ..."
        echo "TD guest is running on port : $TD_GUEST_PORT"
        home_dir=$(cat /etc/passwd | grep $USER | cut -d ":" -f 6)
        if [ -f "$home_dir/.ssh/known_hosts" ]; then
                ssh-keygen -f "$home_dir/.ssh/known_hosts" -R "[localhost]:$TD_GUEST_PORT"
        fi
	while [ $count -lt 3 ]
	do
       		 out=$(sshpass -p "123456" ssh -o StrictHostKeyChecking=no -p 10022 root@localhost 'dmesg | grep -i tdx' 2>&1 )
       		 if [[ "$out" =~ "ssh: connect to host localhost port 10022: Connection refused" ]]; then
       		         sleep 60
       		         count=`expr $count + 1`
       		 elif [[ "$out" =~ "tdx: Guest detected" ]]; then
       		         echo "TDX is configured on guest"
       		         break
       		 elif [[ "$out" =~ "REMOTE HOST IDENTIFICATION HAS CHANGED!" ]]; then
       		         echo "$out"
       		         echo -e "\nERROR : Remove the host key '[localhost]:$TD_GUEST_PORT' $home_dir/.ssh/known_hosts "
       		         echo -e "ERROR: TDX is not properly configured on guest"
       		         break
       		 else
       		         echo "$out"
       		         echo -e "\nERROR: TDX is not properly configured on guest or TD booting is taking more time than usual"
       		         break
       		 fi
	done
	RESULT=$(sshpass -p 123456 ssh -o StrictHostKeyChecking=no -p 10022 root@localhost 'fde-agent --root 123 --name 123 --boot-type 2')
}

cleanup(){
        PID_TD=$(cat /tmp/tdx-demo-td-pid.pid 2> /dev/null)
        [ ! -z "$PID_TD" ] && echo "Cleanup, kill TD vm PID: ${PID_TD}" && kill -TERM ${PID_TD} &> /dev/null
        sleep 3
        rm -f /tmp/tdx-guest-td.log /tmp/tdx-demo-td-pid.pid /tmp/tdx-demo-*-monitor.sock tdx-guest-setup.txt
        rm -rf tdx_verifier
}

apt install --yes sshpass &> /dev/null

launch_td_guest

cleanup
echo $RESULT

