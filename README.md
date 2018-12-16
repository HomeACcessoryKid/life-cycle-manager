# life-cycle-manager (LCM)
Initial install, WiFi settings and over the air firmware upgrades for any esp-open-rtos repository on GitHub  
(c) 2018 HomeAccessoryKid

this readme is still under construction...  
#### Update Mid December 2018
The development area is now here, at LCM repository.
Be aware that this area could show instability while testing alpha and beta versions!!  
DO NOT CONSIDER ANY CODE WITH A RELEASE NUMBER BELOW 1.0.0 OF ANY USE  
unless you are able to re-flash your device if things go wrong.
Having said that, by having introduced the latest-pre-release concept, users (and LCM itself) can test new software before exposing it to production devices.
See the 'How to use it' section.

Meanwhile, at https://github.com/HomeACcessoryKid/ota version 0.1.0 is the version that serves for early starters.  
This software, while having its issues is stable in itself. The idea is that once LCM reaches 1.0.0 there will be a OTA 1.0.0 as well which will switch over the OTA engine to LCM.

https://github.com/HomeACcessoryKid/ota-demo has been upgraded to offer system-parameter editing features which allows for flexible testing of the LCM code.

## Scope
This is a program that allows any simple repository based on esp-open-rtos on esp8266 to solve its life cycle tasks.
- assign a WiFi AccessPoint for internet connectivity
- specify and install the user app without flashing over cable (once the LCM image is in)
- update the user app over the air by using releases and versions on GitHub

## Non-typical solution
The solution is dedicated to a particular set of repositories and devices, which I consider is worth solving.
- Many ESP8266 devices have only 1Mbyte of flash
- Many people have no interest in setting up a software (web)server to solve their upgrade needs
- Many repositories have no ram or flash available to combine the upgrade routines and the user routines
- For repositories that will be applied by MANY people, a scalable software server is needed
- be able to setup wifi securly while not depending on an electrical connection whenever wifi needs setup *)

If all of the above would not be an issue, the typical solution would be to
- combine the usercode and the upgrade code
- load a full new code image side by side with the old proven image
- have a checkpoint in the code that 'proofs' that the upgrade worked or else it will fall back to the old code
- run a server from a home computer at dedicated moments
- setup the wifi password when electrically connected or send it unencrypted and cross fingers no-one is snooping *)

In my opinion, for the target group, the typical solution doesn't work and so LCM will handle it.
Also it turns out that there are no out-of-the-box solutions of the typical case out there so if you are fine with the limitations of LCM, just enjoy it... or roll your own.  
(PS. the balance is much less black and white but you get the gist)  
*) This feature is not yet implemented (it is quite hard), so 'cross your fingers'.

## Benefits
- Having over the air firmware updates is very important to be able to close security holes and prevent others to introduce malicious code
- The user app only requires a few simple lines of code so no increase in RAM usage or complexity and an overall smaller flash footprint
- Through the use of cryptography throughout the life cycle manager, it is not possible for any outside party to squeeze in any malicious code nor to snoop the password of the WiFi AccessPoint *)
- The fact that it is hosted on GitHub means your code is protected by the https certificates from GitHub and that no matter how many devices are out there, it will scale
- The code is publicly visible and can be audited at all times so that security is at its best
- The user could add their own DigitalSignature (ecDSA) although it is not essential. (feature on todolist)
- The producer of hardware could preinstall the LCM code on hardware thereby allowing the final user to select any relevant repository.
- Many off-the-shelf hardware devices have OTA code that can be highjacked and replaced with LCM so no solder iron or mechanical hacks needed (feature on todolist)

## Can I trust you?
If you feel you need 100% control, you can fork this repository, create your own private key and do the life cycle of the LCM yourself.
But since the code of LCM is public, by audit it is unlikely that malicious events will happen. It is up to you. And if you have ideas how to improve on this subject, please share your ideas in the issue #1 that is open for this reason.

## How to use it
User preparation part  
- compile your own code and create a signature (see below)
- in the shell, `echo -n x.y.z > latest-pre-release`
- commit this to Git and sync it with GitHub
- Start a release from this commit and take care the version is in x.y.z format
- Attach/Upload the binary and the signature and create the release _as a pre-release_ **)
- Now go to the current 'latest release', select latest-pre-release to be deleted and then add the new latest-pre-release  
**) except the very first time, you must set it as latest release 

Now test your new code by using a device that you enroll to the pre-release versions (a checkbox in the wifi-setup page).

- If fatal errors are found, just start a new version and leave this one as a pre-release.
- Once a version is approved you can mark it as 'latest release'.
- If a 'latest release' is also the latest release overall, a latest-pre-release is not needed, it points to itself.  

User device setup part  
- clone or fork the LCM repository (or download just the otaboot.bin file)
- wipe out the entire flash (not essential, but cleaner)
- upload these three files:
```
0x0    /Volumes/ESPopenHK/esp-open-rtos//bootloader/firmware_prebuilt/rboot.bin
0x1000 /Volumes/ESPopenHK/esp-open-rtos//bootloader/firmware_prebuilt/blank_config.bin \
0x2000 versions/x.y.zv/otaboot.bin
```
- (or otabootbeta.bin if enrolling in the LCM pre-release testing)
- start the code and wait till the Wifi AP starts.  
- set the repository you want to use in your device. yourname/repository  and name of binary
- then select your Wifi AP and insert your password
- once selected, it will take up to 5 minutes for the system to upload the ota-main software in the second bootsector and the user code in the 1st boot sector
- you can follow progress on the serial port or use the UDPlogger using the command 'nc -kulnw0 45678'

## How it works
todo

## Creating a user app DigitalSignature
from the directory where `make` is run execute:
```
openssl sha384 -binary -out firmware/main.bin.sig firmware/main.bin
printf "%08x" `cat firmware/main.bin | wc -c`| xxd -r -p >>firmware/main.bin.sig
```
