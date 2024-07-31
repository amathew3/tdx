# TDX Full Disk Encryption

Full disk encryption (FDE) is a security method for protecting sensitive
data by encrypting all data on a disk partition. FDE shall encrypt data
automatically to prevent unauthorized access.
This project is a FDE solution based on [Intel&reg; Trust Domain 
Extensions(Intel TDX)](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-trust-domain-extensions.html).

## Architecture

![](../attestation/full-disk-encryption/docs/fde-arch.png)
  
## Preparation

We build the Ubuntu 24.04 guest image on the Ubuntu 24.04 host, and validate it. If you work in other environment, please adapt scripts in the below sections carefully (not recommended).

**Note: The default FDE solution is just a reference implementation. Both fde-agent and fde-image.sh depend on an available KBS (Key Broker Service). Otherwise they cannot work. Please modify fde-agent code to add KBS information before running the solution. The detail can be found in `attestation/full-disk-encryption`.**

### 1. Register a key 

The `key` to encrypt the image disk is distributed by the KBS, besides, which will bind a unique `keyid` with the `key`. The `keyid` is the key's identifier in the KBS. Consult your KBS to get a pair of key and key_id.

### 2. Build the fde-agent
Clone the repo `https://github.com/amathew3/tdx/tree/noble-24.04`
```
cd tdx
FDE_DIR=$PWD/attestation/full-disk-encryption

The fde-agent is placed in the `FDE_DIR`. 

The fde-agent is responsible for decrypting a guest image and mounting it as the rootfs. The fde-agent depends on dynamic libraries `libtdx-attest` and `libtdx-attest-dev` in `DCAP`.This package can be installed using below commands.

```
sudo apt install -y libtdx-attest libtdx-attest-dev
cd $FDE_DIR
make clean -C ../full-disk-encryption
make -C ../full-disk-encryption
```

### 3. Create FDE image

There are several ways to create FDE image. The [wiki page](https://help.ubuntu.com/community/Full_Disk_Encryption_Howto_2019) in Ubuntu community provides a base knowledge. Besides, install fde-agent and initramfs-tools in this repo. Finally, append the option `cryptdevice` in the kernel command (refer [link](https://wiki.archlinux.org/title/dm-crypt/System_configuration)) and then update the Grub config.

For retrieving the TD properties build a sample encrypted image first. Use dummy values for generating this image.
Copy your public key as `public.pem` to $FDE_DIR before doing the below steps.
```
KEY=123456
KEY_ID=b8a5f372-5793
KBS_URL=http://127.0.0.1:8002
cd ${FDE_DIR}/tools/image
sudo ./fde-image.sh -k $KEY -i $KEY_ID -u $KBS_URL -f 1
sudo chown $USER:$USER OVMF_FDE.fd
sudo chown $USER:$USER td-guest-ubuntu-24.04-encrypted.img
cd ../../
```

The encrypted image and updated OVMF files will be generated in the current folder.
Run the `tdx_guest_load.sh` script, this will boot the TD using the generated image and OVMF.
The script will print the TD properties and quote data to the console.
'''
./tdx_guest_load.sh
export QUOTE=<copied content>
export MRTD=<copied content>
export MRSEAM=<copied content>
export USER_NAME=<kbs_admin_user>
export PASSWORD=<kbs_password>
export KBS_URL=<KBS uRL>

curl --cacert /etc/kbs/certs/tls/tls.crt  --location "$KBS_URL/kbs/v1/token"  --header 'Accept: application/jwt'  --header 'Content-Type: application/json'  --data "{    \"username\": \"$USERNAME\",    \"password\": \"$PASSWORD\" }"

export BEARER_TOKN="<copied content>"

curl  --cacert /etc/kbs/certs/tls/tls.crt   --location "$KBS_URL/kbs/v1/key-transfer-policies"  --header 'Accept: application/json'  --header 'Content-type: application/json'   --header "Authorization: Bearer ${BEARER_TOKEN}" --data "{    \"attestation_type\": \"TDX\",      \"tdx\": { \"attributes\": {\"mrsignerseam\": [\"$MRSIGNERSEAM\"],\"mrseam\": [\"$MRSEAM\"],\"mrtd\": [\"$MRTD\"],\"seamsvn\": 4, \"enforce_tcb_upto_date\": false } } }"
export POLICY_ID=<copy id  from output>

curl  --cacert /etc/kbs/certs/tls/tls.crt --location "$KBS_URL/kbs/v1/keys"  --header 'Accept: application/json'  --header 'Content-type: application/json'   --header "Authorization: Bearer ${BEARER_TOKEN}" --data "{\"key_information\": { \"algorithm\":\"RSA\", \"key_length\":3072 }, \"transfer_policy_id\" : \"$POLICY_ID\"}"

export KEY_TRANSFER_LINK=<copied_content>

'''
For detailed steps  refere to this link  `https://github.com/intel/trustauthority-kbs.git`

Once the key transfer policy is set in KBS, retrieve the wrapped_swk and wrapped_key using the quote retrieved in step3.
run the following binary `fde-key-gen`
Expected to have your private key file as `private.pem` in /etc directory before invoking the script.
```
cd $FDE_DIR/fde-key-gen
make
./fde-key-gen --transfer-link $KEY_TRANSFER_LINK --quote-bytes $QUOTE --url $URL
```

this will return the FDE key for encrypting the image.
```
KEY=<output of fde_key>
cd ${FDE_DIR}/tools/image
sudo ./fde-image.sh -k $KEY -i $KEY_TRANSFER_LINK -u $KBS_URL -f 3
sudo chown $USER:$USER OVMF_FDE.fd
sudo chown $USER:$USER td-guest-ubuntu-24.04-encrypted.img
cd ../../
```


### 4. Enroll variables to OVMF

Installing ovmfkeyenroll tool and inserting Key broker Service information into OVMF will be taken care in `fde-image.sh` script.

### TDX tools 

The script `run_td.sh` helps launch a TDX guest from an encrypted guest image built through above steps. 
```
TD_IMG=tools/image/td-guest-ubuntu-24.04-encrypted.img ../../guest-tools/run_td.sh -f -o tools/image/OVMF_FDE.fd
-f to enable full disk encryption
-o specify the updated OVMF path
```

## Validation

Launch a tdvm guest by the following command. 

```
TD_IMG=<absolute path of encrypted image> ../../guest-tools/run_td.sh -f -o <OVMF.fd path>

```

Verify the encryption status by running the command in the tdvm guest.

```
blkid
```

The TYPE of encrypted partition should be `crypto_LUKS`

```
/dev/vda1: UUID="79c64ac3-c2c2-479b-bbd8-ea9c7d5cf29f" LABEL="cloudimg-rootfs-enc" TYPE="crypto_LUKS"
```
