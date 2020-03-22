# Changelog

## 1.9.5 Fix bootflags when uploading rboot
- The uploading of a bootloader to sector 0 should replicate the flags1 and flags2 values of the previous bootloader.
Else it will break the access to the flash in case it is not compatible.
- esp-open-rtos used has been updated from  [esp-open-rtos#a721fb0](https://github.com/SuperHouse/esp-open-rtos/commit/a721fb0bc7867ef421cd81fb89d486ed2a67ee9e) 
to [esp-open-rtos#bc97988](https://github.com/SuperHouse/esp-open-rtos/commit/bc979883c27ea57e948daa813e2bca752ebd39e1)  
- change the verification of the signature of otamain.bin prior to downloading this file instead of afterwards

## 1.9.4 and before will be updated in the future