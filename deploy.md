(c) 2018 HomeAccessoryKid

Instructions for end users:
TBD

#Instructions if you own the private key:
```
cd life-cycle-manager
```
#initial steps to be expanded

#create/update the file versions1/latest-pre-release but no new-line
```
echo -n 0.9.5 > versions1/latest-pre-release
mkdir versions1/0.9.5v
cp versions1/certs.sector* versions1/0.9.5v
cp versions1/public*key.sig versions1/0.9.5v
```
#set local.mk to the ota-main program
```
make -j6 rebuild OTAVERSION=0.9.5
mv firmware/otamain.bin versions1/0.9.5v
```
#set local.mk back to ota-boot program
```
make -j6 rebuild OTAVERSION=0.9.5
mv firmware/otaboot.bin versions1/0.9.5v
make -j6 rebuild OTAVERSION=0.9.5 OTABETA=1
cp firmware/otaboot.bin versions1/0.9.5v/otabootbeta.bin
```

#remove the older versions files

#commit this as version 0.9.5
#set up a new github release 0.9.5 as a pre-release using the just commited master...
#upload the certs and binaries to the pre-release assets on github

#erase the flash and upload the privatekey
```
esptool.py -p /dev/cu.usbserial-* --baud 230400 erase_flash 
esptool.py -p /dev/cu.usbserial-* --baud 230400 write_flash 0xf5000 versions1-privatekey.der
```
#upload the ota-boot BETA program to the device that contains the private key
```
make flash OTAVERSION=0.9.5 OTABETA=1
```
#power cycle to prevent the bug for software reset after flash
#setup wifi and select the ota-demo repo without pre-release checkbox
#create the 2 signature files next to the bin file and upload to github one by one
#verify the hashes on the computer
```
openssl sha384 versions1/0.9.5v/otamain.bin
xxd versions1/0.9.5v/otamain.bin.sig
```

#upload the file versions1/latest-pre-release to the 'latest release' assets on github

#test the release with several devices that have the beta flag set
#if bugs are found, leave this release at pre-release and start a new version

#if the results are 100% stable
#make the release a production release on github
#remove the private key
```
esptool.py -p /dev/cu.usbserial-* --baud 230400 write_flash 0xf5000 versions1/blank.bin
```


#how to make a new signing key pair

#use the finder to duplicate the content from the previous versions folder => call it versions1
#remove all the duplicates that will not change from the previous versions folder

#make a new key pair
```
mkdir /tmp/ecdsa
cd    /tmp/ecdsa
openssl ecparam -genkey -name secp384r1 -out secp384r1prv.pem
openssl ec -in secp384r1prv.pem -outform DER -out secp384r1prv.der
openssl ec -in secp384r1prv.pem -outform DER -out secp384r1pub.der -pubout
cat secp384r1prv.pem
```
#capture the private key pem in a secret place and destroy .pem and .der from here

#open certs.hex and replace the first 4 rows with the public key xxd output
```
xxd -p secp384r1pub.der
xxd -p -r certs.hex > certs.sector
```
#start a new release as described above, but in the first run, use the old private key in 0xf5000

#make a public-1.key.sig which needs to be added to every new version
#if a public-1.key.sig already exists, this would then be renamed to public-2.key.sig etc...
#then flash the new private key
```
esptool.py -p /dev/cu.usbserial-* --baud 230400 write_flash 0xf5000 versions2-privatekey.der
```

