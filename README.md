# Life-Cycle-Manager (LCM)
Initial install, WiFi settings and over the air firmware upgrades for any esp-open-rtos repository on GitHub  
(c) 2018-2022 HomeAccessoryKid

## Update season 16 April 2022
After 14 months, version 2.1.2 will get upgraded to version 2.2.5. So be aware your own app update will take extra long.  
It would be recommendable to also update devices that do not have an user app update.  
Not that 2.1.2 is broken or in danger, but 2.2.5 is more future proof.

## Version
[Changelog](https://github.com/HomeACcessoryKid/life-cycle-manager/blob/master/Changelog.md)  
With version 2.0.0 LCM has arrived to a new stage with its own adaptation of rboot - rboot4lcm - which counts powercycles.
These are used to check updates, reset wifi, clear or set LCM_beta or factory reset. It also gives access to the emergency mode.  
Setting a value for a led_pin visual feedback is possible.
By having introduced the latest-pre-release concept in version 1.0.0, users (and LCM itself) can test new software before exposing it to production devices.
See the 'How to use it' section.

https://github.com/HomeACcessoryKid/ota-demo has been upgraded to offer system-parameter editing features which allows for flexible testing of the LCM code.

## Scope
This is a program that allows any simple repository based on esp-open-rtos on esp8266 to solve its life cycle tasks.
- assign a WiFi AccessPoint for internet connectivity
- specify and install the user app without flashing over cable (once the LCM image is in)
- assign app specific and device specific parameters
- update the user app over the air by using releases and versions on GitHub

## New features version 2

This new LCM code is able to load/update the bootloader from github.  
The new bootloader is able to count the amount of short power cycles (<1.5s)  
From the second cycle the cycles must be shorter than 4 seconds. Also a LED is lit if defined.  
The boot loader conveys the count to the loaded code using the rtc.temp_rom value  
User code is allowed the values from 1-4  
- 1  : this is a normal boot
- 2-4: users choice in user code (communicate 3 to user or risk a bit and use 2, 3 and 4 separatly)

If count > 4 the bootloader launches LCM otamain.bin in rom[1]  

For these values the behaviour is controlled through the sysparam string `ota_count_step`.  
The default value of 3 reduces the chance of user misscounting and triggering something else than intended or playfull children.

Note that with LCM_beta mode and wifi erased you can set any emergency fallback server to collect a new signed version of otaboot.bin.
This is to prevent a lockout as witnessed when Github changed their webserver in 2020.  
Tested with macOS [builtin apache server](https://discussions.apple.com/docs/DOC-13841).  
By monitoring the output with the terminal command `nc -kulnw0 45678` you have 10 seconds to see which action was chosen before it executes.

If `ota_count_step=="3"` (default)
- 5-7: check for new code  (communicate 6 to user)
- 8-10: erase wifi info and clear LCM_beta mode (communicate 9 to user)
- 11-13: erase wifi info and set LCM_beta mode and gain access to emergency mode (communicate 12 to user)
- 14-16: factory reset (communicate 15 to user)

If `ota_count_step=="2"`
- 5-6: check for new code  (communicate 5 to user)
- 7-8: erase wifi info and clear LCM_beta mode (communicate 7 to user)
- 9-10: erase wifi info and set LCM_beta mode and gain access to emergency mode (communicate 9 to user)
- 11-12: factory reset (communicate 11 to user)

If `ota_count_step=="1"`
- 5: check for new code  (communicate 5 to user)
- 6: erase wifi info and clear LCM_beta mode (communicate 6 to user)
- 7: erase wifi info and set LCM_beta mode and gain access to emergency mode (communicate 7 to user)
- 8: factory reset (communicate 8 to user)

Missing or other `ota_count_step` values will be interpreted as 3

In version 2.2.5 there are two new features:
There is a new possibility for those user apps that need some configuration data to work that is specific to each instantiation.
One can set the `ota_string` parameter which can be parsed by the user app to set e.g. MQTT server, user and password or whatever else you fancy.
Since it is up to the user app to parse it, you test whatever works for you within the cgi transfer of parameters.
Also, using the 'erase wifi' mode, new settings can be set again when needed.

There also exists the possibility to set the sysparam `ota_count` to activate the 'erase wifi' etc from the user app as well.


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
User code preparation part
- in an appropriate part of your code, add these two function calls which will trigger an update if you want to:
- ```rboot_set_temp_rom(1); //select the OTA main routine```
- ```sdk_system_restart();  //#include <rboot-api.h>```
- there is a bug in the esp SDK such that if you do not power cycle the chip after flashing, restart is unreliable
- compile your own code and create a signature (see below)
- in the shell, `echo -n x.y.z > latest-pre-release`
- commit this to Git and sync it with GitHub
- Start a release from this commit and take care the version is in x.y.z format
- Attach/Upload the binary and the signature and create the release _as a pre-release_ **)
- Now go to the current 'latest release', ie the non-pre-release one you’re about to improve upon, edit its list of assets and either add or remove and replace the `latest-pre-release` file so that we now have a pointer to the pre-release we created above  
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
0x0    <path_to>/esp-open-rtos/bootloader/firmware_prebuilt/rboot.bin
0x1000 <path_to>/esp-open-rtos/bootloader/firmware_prebuilt/blank_config.bin
0x2000 <release>/otaboot.bin
```
- (or otabootbeta.bin if enrolling in the LCM pre-release testing)
- start the code and either use serial input menu or wait till the Wifi AP starts.  
- set the repository you want to use in your device: `yourname/repository`  and name of binary
- then select your Wifi AP and insert your password
- once selected, it will take up to 5 minutes for the system to download the ota-main software in the second bootsector and the user code in the 1st boot sector
- you can follow progress on the serial port or use the UDPlogger using the terminal command `nc -kulnw0 45678`

## Creating a user app DigitalSignature
from the directory where `make` is run execute:
```
openssl sha384 -binary -out firmware/main.bin.sig firmware/main.bin
printf "%08x" `cat firmware/main.bin | wc -c`| xxd -r -p >>firmware/main.bin.sig
```

## How it works
This design serves to read through the code base.
The actual entry point of the process is the self-updater which is called ota-boot and which is flashed by serial cable.

![](https://github.com/HomeACcessoryKid/life-cycle-manager/blob/master/design-v5.png)

### Concepts
```
User app(0)
v.X triggers
```
The usercode Main app is running in bootslot 0 at version x. It can trigger a switch to bootslot 1.  
Also the tuned bootloader [rBoot4LCM](https://github.com/HomeACcessoryKid/rboot4lcm) can switch to bootslot 1.

```
powercycles select:
```
Based on the number of cycles, we will check for new versions, reset the wifi parameters or with lcmbeta allow the setting of an emergency server.
Choosing factory reset will erase all the usercode and parameters so no sensitive data stays behind.
After this the normal update cycle starts, except if an emergency server is defined

```
use http://not.github.com/somewhere/
```
After resetting wifi and selecting lcmbeta mode (12 power cycles) the user can specify another base location where the files otaboot.bin.sig and otaboot.bin will be collected.
This enters emergency mode. If the signature is valid against the public key of LCM then it will replace the bootslot 0 and continue to update otamain etc. 
```
(t)
```
This represents an exponential hold-off to prevent excesive hammering on the github servers. It resets at a power-cycle.

```
download certificate signature
certificate update?
Download Certificates
```
This is a file that contains the checksum of the sector containing three certificates/keys
- public key of HomeACessoryKid that signs the certificate/key sector 
- root CA used by GitHub
- root CA used by the DistributedContentProvider (now GitHub's own, Amazon before release 2.1.0)

Once downloaded, the signature is checked against the known public key and the sha384 checksum of the active sector is compared to the checksum in the signature file. If equal, we move on. If not, we download the updated sector file to the standby sector.

```
signature match?
```
From the sector containing up to date certificates the sha384 hash has been signed by the private key of LCM.
Using the available public key, the validity is verified. 
From here, the files are intended to be downloaded with server certificate verification activated. If this fails, the server is marked as invalid.

```
new boot version?
```
This will download the latest version of [rboot4lcm](https://github.com/HomeACcessoryKid/rboot4lcm)

```
new OTA version?
download OTA-boot➔0
update OTA-main➔1
sig & checksum OK?
```

We verify if there is an update of this OTA repo itself? If so, we use ota-boot to self update. After this we have the latest OTA code.

```
server valid?
```
If by checking the certificates the server is marked invalid, we return to the main app in boot slot 0 and we report by syslog to a server (to be determinded) so we learn that github has changed its certificate CA provider and HomeACessoryKid can issue a new certificate sector.  
Now that the downloading from GitHub has been secured, we can trust whatever we download based on a checksum.

```
OTA-main(1) updates User app➔0
sig & checksum OK?
```
Using the baseURL info and the version as stored in sysparam area, the latest binary is found and downloaded if needed. If the checksum does not work out, we return to the OTA app start point considering we cannot run the old code anymore.
But normally we boot the new code and the mission is done.

Note that switching from boot=slot1 to boot=slot0 does not require a reflash



## AS-IS disclaimer and License
While I pride myself to make this software error free and backward compatible and otherwise perfect, this is the 
result of a hobby etc. etc. etc. So don't expect me to be responsible for anything...

See the LICENSE file for license information
