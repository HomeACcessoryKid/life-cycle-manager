# life-cycle-manager (LCM)
Initial install, WiFi settings and over the air firmware upgrades for any esp-open-rtos repository on GitHub

this readme is under construction...  
Meanwhile, the development area is at https://github.com/HomeACcessoryKid/ota  
Be aware that this area could show instability while testing alpha and beta versions!!  
DO NOT CONSIDER ANY CODE WITH A RELEASE NUMBER BELOW 1.0.0 OF ANY USE

## Scope
This is a program that allows any simple repository based on esp-open-rtos on esp8266 to solve its life cycle tasks.
- assign a WiFi AccessPoint for internet connectivity
- specify and install the user app without flashing over cable
- update the user app over the air by using releases and versions on GitHub

## Non-typical solution
The solution is dedicated to a particular set of repositories and devices, which I consider is worth solving.
- Many ESP8266 devices have only 1Mbyte of flash
- Many people have no interest in setting up a software (web)server to solve their upgrade needs
- Many repositories have no ram or flash available to combine the upgrade routines and the user routines
- For repositories that will be applied by MANY people, a scalable software server is needed
- be able to setup wifi securly while not depending on an electrical connection whenever wifi needs setup

If all of the above would not be an issue, the typical solution would be to
- combine the usercode and the upgrade code
- load a full new code image side by side with the old proven image
- have a checkpoint in the code that 'proofs' that the upgrade worked or else it will fall back to the old code
- run a server from a home computer at dedicated moments
- setup the wifi password when electrically connected or send it unencrypted and cross fingers no-one is snooping

In my opinion, for the target group, the typical solution doesn't work and so LCM will handle it.
Also it turns out that there are no out-of-the-box solutions of the typical case out there so if you are fine with the limitations of LCM, just enjoy it... or roll your own.  
(PS. the balance is much less black and white but you get the gist)

## Benefits
- Having over the air firmware updates is very important to be able to close security holes and prevent others to introduce malicious code
- The user app only requires a few simple lines of code so no increase in RAM usage or complexity and an overall smaller flash footprint
- Through the use of cryptography throughout the life cycle manager, it is not possible for any outside party to squeeze in any malicious code nor to snoop the password of the WiFi AccessPoint
- The fact that it is hosted on GitHub means your code is protected by the https certificates from GitHub and that no matter how many devices are out there, it will scale
- The code is publicly visible and can be audited at all times so that security is at its best
- The user could add their own DigitalSignature (ecDSA) although it is not essential. (feature on todolist)
- The producer of hardware could preinstall the LCM code on hardware thereby allowing the final user to select any relevant repository.
- Many off-the-shelf hardware devices have OTA code that can be highjacked and replaced with LCM so no solder iron or mechanical hacks needed (feature on todolist)

## Can I trust you?
If you feel you need 100% control, you can fork this repository, create your own private key and do the life cycle of the LCM yourself.
But since the code of LCM is public, by audit it is unlikely that malicious events will happen. It is up to you. And if you have ideas how to improve on this subject, please share your ideas in the issue #1 that is open for this reason.

## How to use it
User part  
- compile your own code and create a signature (see below).
- commit this to Git and sync it with GitHub
- Start a release from this commit and take care the version is in x.y.z format
- Attach/pload the binary and the signature and create the release (it should now be marked as 'latest release')

LCM part
- Clone or fork the LCM repository, wipe out the entire flash (not essential, but cleaner) and upload the otaboot.bin
- start the code and wait till the Wifi AP starts.  
- select your Wifi and also set the repository you want to use in your device. yourname/repositry  and name of binary
- once selected, it will take up to 5 minutes for the system to upload the ota-main software in the second bootsector and the user code in the 1st boot sector

## How it works
todo

## Creating a user app DigitalSignature
from the directory where `make` is run execute:
```
openssl sha384 -binary -out firmware/main.bin.sig firmware/main.bin
printf "%08x" `cat firmware/main.bin | wc -c`| xxd -r -p >>firmware/main.bin.sig
```
