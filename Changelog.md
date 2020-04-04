# Changelog

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

## 1.9.4 and before will be updated in the future