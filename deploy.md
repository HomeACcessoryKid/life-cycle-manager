(c) 2018 HomeAccessoryKid

Instructions for end users:
TBD

#Instructions if you own the private key:
```
cd life-cycle-manager
```
#initial steps to be expanded

#create/update the file versions/latest-pre-release but no new-line
```
echo -n 0.1.12 > versions/latest-pre-release
mkdir versions/0.1.12v
cp versions/certs.sector versions/0.1.12v
```
#set local.mk to the ota-main program
```
make -j6 rebuild OTAVERSION=0.1.12
mv firmware/otamain.bin versions/0.1.12v
```
#set local.mk back to ota-boot program
```
make -j6 rebuild OTAVERSION=0.1.12
mv firmware/otaboot.bin versions/0.1.12v
make -j6 rebuild OTAVERSION=0.1.12 OTABETA=1
cp firmware/otaboot.bin versions/0.1.12v/otabootbeta.bin
```

#remove the older versions files

#commit this as version 0.1.12
#set up a new github release 0.1.12 as a pre-release using the just commited master...
#upload the certs and binaries to the pre-release assets on github

#erase the flash and upload the privatekey
```
esptool.py -p /dev/cu.usbserial-* --baud 230400 erase_flash 
esptool.py -p /dev/cu.usbserial-* --baud 230400 write_flash 0xf5000 privatekey.der
```
#upload the ota-boot BETA program to the device that contains the private key
```
make flash OTAVERSION=0.1.12 OTABETA=1
```
#power cycle to prevent the bug for software reset after flash
#create the 3 signature files next to the bin file and upload to github one by one
#verify the hashes on the computer
```
openssl sha384 versions/0.1.12v/otamain.bin
xxd versions/0.1.12v/otamain.bin.sig
```

#upload the file versions/latest-pre-release to the 'latest release' assets on github

#test the release with several devices that have the beta flag set
#if bugs are found, leave this release at pre-release and start a new version

#if the results are 100% stable
#make the release a production release on github
#remove the private key
```
esptool.py -p /dev/cu.usbserial-* --baud 230400 write_flash 0xf5000 versions/blank.bin
```
