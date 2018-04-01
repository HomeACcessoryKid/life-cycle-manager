# life-cycle-manager (LCM)
Initial install, WiFi settings and over the air firmware upgrades for any esp-open-rtos repository on GitHub

this readme is under construction...

## Scope
This is a program that allows any simple repository based on esp-open-rtos on esp8266 to solve its life cycle tasks.
- assign a WiFi AccessPoint for internet connectivity
- specify and install the user app without flashing over cable
- update the user app over the air by using releases and versions on GitHub

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
todo

## How it works
todo

## Creating a user app DigitalSignature
todo
