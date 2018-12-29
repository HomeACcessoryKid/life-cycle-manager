(c) 2018 HomeAccessoryKid

### Instructions for end users:
TBD

### Instructions if you own the private key:
```
cd life-cycle-manager
```
- initial steps to be expanded

#### These are the steps if not introducing a new key pair
- create/update the file versions3/latest-pre-release without new-line and setup 0.9.13 version folder
```
echo -n 0.9.13 > versions3/0.9.13v/latest-pre-release
mkdir versions3/0.9.13v
cp versions3/certs.sector* versions3/0.9.13v
cp versions3/public*key*   versions3/0.9.13v
```
- set local.mk to the ota-main program
```
make -j6 rebuild OTAVERSION=0.9.13
mv firmware/otamain.bin versions3/0.9.13v
```
- set local.mk back to ota-boot program
```
make -j6 rebuild OTAVERSION=0.9.13
mv firmware/otaboot.bin versions3/0.9.13v
make -j6 rebuild OTAVERSION=0.9.13 OTABETA=1
cp firmware/otaboot.bin versions3/0.9.13v/otabootbeta.bin
```
- remove the older version files
#
- commit this as version 0.9.13  
- set up a new github release 0.9.13 as a pre-release using the just commited master...  
- upload the certs and binaries to the pre-release assets on github  
#
- erase the flash and upload the privatekey
```
esptool.py -p /dev/cu.usbserial-* --baud 230400 erase_flash 
esptool.py -p /dev/cu.usbserial-* --baud 230400 write_flash 0xf5000 versions3-privatekey.der
```
- upload the ota-boot BETA program to the device that contains the private key
```
make flash OTAVERSION=0.9.13 OTABETA=1
```
- power cycle to prevent the bug for software reset after flash  
- setup wifi and select the ota-demo repo without pre-release checkbox  
- create the 2 signature files next to the bin file and upload to github one by one  
- verify the hashes on the computer  
```
openssl sha384 versions3/0.9.13v/otamain.bin
xxd versions3/0.9.13v/otamain.bin.sig
```

- upload the file versions3/0.9.13v/latest-pre-release to the 'latest release' assets on github

#### Testing

- test the release with several devices that have the beta flag set  
- if bugs are found, leave this release at pre-release and start a new version
#
- if the results are 100% stable  
- make the release a production release on github  
- remove the private key  
```
esptool.py -p /dev/cu.usbserial-* --baud 230400 write_flash 0xf5000 versions3/blank.bin
```


### How to make a new signing key pair

- use the finder to duplicate the content from the previous versions folder => call it versions3  
- push all existing public-N.key.sig and public-N.key files one number up  
- e.g. if a public-2.key.sig already exists, this would then be renamed to public-3.key.sig etc...  
- rename the duplicated cert.sector to public-2.key
- note the new certs.sector is public-1.key but we never need to call it with that name  
- remove all the duplicates that will not change from the previous versions folder like blank.bin ...  
- note a public-N.key.sig is a signature on a certs.sector file, but using an older key  
- and certs.sector.sig is also a signature on a certs.sector file, but using its own key  
- there is no need to upload or even keep public-N.key for versionsN since it is never needed  
#
- make a new key pair
```
mkdir /tmp/ecdsa
cd    /tmp/ecdsa
openssl ecparam -genkey -name secp384r1 -out secp384r1prv.pem
openssl ec -in secp384r1prv.pem -outform DER -out secp384r1prv.der
openssl ec -in secp384r1prv.pem -outform DER -out secp384r1pub.der -pubout
cat    secp384r1prv.pem
xxd -p secp384r1pub.der
```
- capture the private key pem in a secret place and destroy .pem and .der from /tmp

- open certs.hex and replace the first 4 rows with the public key xxd output, then make the new certs.sector
```
vi versions3/certs.hex; xxd -p -r versions3/certs.hex > versions3/certs.sector
```
- start a new release as described above, but in the first run, use the previous private key in 0xf5000
```
esptool.py -p /dev/cu.usbserial-* --baud 230400 write_flash 0xf5000 versionsN-1-privatekey.der
```
- collect public-1.key.sig and store it in the new version folder and copy it to versions3
```
cp  versions3/0.9.13v/public-1.key.sig versions3
```
- then flash the new private key
```
esptool.py -p /dev/cu.usbserial-* --baud 230400 write_flash 0xf5000 versions3-privatekey.der
```
- collect cert.sector.sig and store it in the new version folder and copy it to versions3 
```
cp  versions3/0.9.13v/certs.sector.sig versions3
```
- continue with a normal deployment to create the 2 signature files next to the bin files
