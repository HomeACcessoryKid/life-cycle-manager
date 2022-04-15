# Changelog

## 2.2.5 updated certificates to be identical across all versions
- contains DigiCertGlobalRootCA and DigiCertHighAssuranceEVRootCA
- EC support put back in place
- flow diagram still not updated

## 2.2.4 TEST: new scheme without initial certificate checking
- to test, made it broken without EC support (like 2.2.0)
- added a sysparam ota_count to set LCM outcomes also from user space
- now requires a full signature on rboot4lcm binary
- flow diagram not yet updated

## 2.2.3 updated GitHub root CA certificate
- since the new certificates use EllipticCurve, versions prior to 2.2.1 crash when checking cert
- note that the usage of EC makes the TLS process a lot slower

## 2.2.2 updated README and fixed wifi-config repo commit
- removed now outdated info from README
- the commit to wifi-config was not synced to github and got rolled back
  which meant that the hash code changed, even though the code did not...
  now added one cosmetic change after all

## 2.2.1 fixed support for ECDHE in TLS protocol
- even though these protocols were offered in the ClientHello, they were broken
- the supporting extensions were missing and the server never selected them

## 2.2.0 more robust parsing of Location header and added ota_string
- even long headers existing before the Location header will be parsable
- ota_string sysparam added to pass configuration to user app

## 2.1.2 creating smaller otamain.bin with -Os
- because 2.1.1 otamain was too big and clobbered sysparam area

## 2.1.1 introduced SNI extension to fix issue created by GitHub new CDN
- without SNI the server presents the wrong certificate
- no need to add the intermediate certificate since it is offered by the server
- this means the certificate file remains the same as in version 2.0.2

## 2.1.0 updated to the new certificate used by GitHub for the content distribution server
- GitHub switched to their own domain and now use a DigiCert CA instead of Baltimore CA
- make a final 0x0a and or 0x0d optional for the prerelease file
- fixed an exception if user did not provide proper .sig file

## 2.0.2 overwrite RavenSystem/haa filename with lcm special version
- this special version uses sysparam definition compatible with lcm 

## 2.0.1 fix serial config menu after confirm stalling

## 2.0.0 stable new version with new functions
- rboot4lcm gives control regardless of the user code
- emergency mode allows to replace code OTA without dependency of GitHub
- ability to define a led pin for visual feedback
- load initial certificate from inside otaboot.bin
- see the change log below for all the details

## 2.0.0 when using serial config, set ota_version=0.0.0

## 1.9.12 added led option to the serial config menu

## 1.9.11 led back to input mode after restart
- if not, led continues output in last state

## 1.9.10 introduced blinking led feedback
- uses the sysparam led_pin and starts blinking only from ota_init onwards
- cosmetic fixes to design diagram

## 1.9.9 increased stack size for logsend and pre-wifi tasks
- these were showing high watermark errors in testing 1.9.8
- cosmetic changes to count-down messages

## 1.9.8 starting udplogger earlier better
- wifi won't start until user_init is over so created a pre-wifi-task

## 1.9.7 start udplogger earlier and fix new safari issue
- a tiny fix in wifi_config solves an incompatability with new Safari versions (macOS
10.15.4 and iOS 13.4)
- a non-working attempt to make sure the count down messages show up in `nc -kulnw0 45678`

## 1.9.6 process led_pin info and grace period for power cycles
- the wifi page allows setting info about the led pin.
- choices are for GPIO 2, 4, 5, 13, 14, 15 since these are the least likely to create hardware issues
- default is that the led is connected to +Vcc and is active on '0'
- if your led connects to GND then you can check the box to indicate it is active on '1'
- the led info is stored in sysparam_int8 led_pin and parsing is done for all values between -15 and 15
- the values below zero indicate the led is active on '1'
- Also, if count>4 from rboot4lcm then a message counting down from 10 allows abort in case of mistake
- It is recommended to ALWAYS monitor LCM via `nc -kulnw0 45678` to check for these messages

## 1.9.5 Fix bootflags when uploading rboot
- The uploading of a bootloader to sector 0 should replicate the flags1 and flags2 values of the previous bootloader.
Else it will break the access to the flash in case it is not compatible.
- esp-open-rtos used has been updated from  [esp-open-rtos#a721fb0](https://github.com/SuperHouse/esp-open-rtos/commit/a721fb0bc7867ef421cd81fb89d486ed2a67ee9e) 
to [esp-open-rtos#bc97988](https://github.com/SuperHouse/esp-open-rtos/commit/bc979883c27ea57e948daa813e2bca752ebd39e1)  
- change the verification of the signature of otamain.bin prior to downloading this file instead of afterwards

## 1.9.4 load initial cert from inside OTABOOT plus details
- clear lcm_beta instead of setting it to 0
- allow for missing trailing / in emergency base URL
- updated README.md and design diagram
- changed order for checking otaboot.sig

## 1.9.3 clear LCM_beta after emergency
- this didn't actually work

## 1.9.2 first test of LANmode fallback
- after GitHub changed their http header this allows to recover
- also called emergency mode

## proof of concept emergency mode

## 1.9.1 fix to make http header parsing more robust
- after GitHub changed the syntax of Location: to location:

## Fixes bug caused by GitHub header changes (#22) 
- Fixes case sensitive headers.
- Makes blank space optional for some headers.
- Rename strstr_lc() function to ota_strstr().
- Added '\n' to the beginning of some headers.

## 1.9.0 transfer from LCMdev 1.2.5
- LCM has arrived to a new stage with its own adaptation of rboot -
rboot4lcm - which counts powercycles. These can be used to check
updates, reset wifi or factory reset.
The versions 1.9.x will test at beta level what was started in the repo
LCMdev v1.2.5 and lead up to version 2.0.0

## updates done in LCMdev
- 1.2.5 really erase wifi settings and fix ota_beta readout
- 1.2.4 changed ota_count_step to sysparam string
- 1.2.3 ota_count_step defines power cycle behaviour
- 1.2.2 documentation update
- 1.2.2 improved wifi reset code
- 1.2.1 fixed wifi erase and ota_new_layout
- 1.2.0 read rtc power cycle count and reduce ota-main binary
- 1.1.2 fix boot bits init and serial input
- 1.1.1 fixed the position of boot update code to ota-main-only
- 1.1.0 added update of boot loader and minor fixes
- 1.0.1 initial adjustments after cloning 
- 1.0.0 clone of Life-Cycle-Manager 1.0.0

## completed instructions how to integrate with esp-homekit
