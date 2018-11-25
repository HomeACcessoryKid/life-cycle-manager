Instructions for end users:
TBD

#Instructions if you own the private key:
```
cd life-cycle-manager
```
#initial steps to be expanded

mkdir versions/0.1.8v
cp versions/certs.sector versions/0.1.8v
#set local.mk to the ota-main program
make -j6 rebuild OTAVERSION=0.1.8
mv firmware/otamain.bin versions/0.1.8v
#set local.mk back to ota-boot program
make -j6 rebuild OTAVERSION=0.1.8
cp firmware/otaboot.bin versions/0.1.8v

#remove the older versions files

#commit this as version 0.1.8
#set up a new github release 0.1.8 as a pre-release using the just commited master...

#erase the flash and upload the privatekey
```
esptool.py -p /dev/cu.usbserial-* --baud 230400 erase_flash 
esptool.py -p /dev/cu.usbserial-* --baud 230400 write_flash 0xf5000 privatekey.der
```
#upload the ota-boot program to the device that contains the private key
make flash OTAVERSION=0.1.8
#power cycle to prevent the bug for software reset after flash
#create the 3 signature files next to the bin file and upload to github one by one
#verify the hashes on the computer
openssl sha384 versions/0.1.8v/otamain.bin
xxd versions/0.1.8v/otamain.bin.sig
#make the release a production release on github
#remove the private key
```
esptool.py -p /dev/cu.usbserial-* --baud 230400 write_flash 0xf5000 versions/blank.bin
```
