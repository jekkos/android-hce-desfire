

Project Inception
-----------------

This project is an incomplete software implementation of the Mifare Desfire protocol for HCE on Android.
The app has to be used with the original HCE patch of Doug Yeager introduced in CyanogenMod 9. Most of the
initial code has now been removed from CyanogenMod and thus a system level patch is needed to make the whole work.

* App will only work on phones with PN544 NXP chip (which are HTC One M7, Nexus S, ..)
* A patched NFC.apk will need to be built from the packages_Nfc_apps repository I cloned here on github
* libnfc-nxp should contain the needed fixes in CM12 (no changes required)

Project state
-------------

The code contains some testcases that verify a couple of different basic communication scenario's with a DesFire card. 
Doug Yeager's patch was ported to Android 5 which enabled a pn544 to communicate with off the shelve NFC physical security system at Capgemini Belgium's premises.
[A talk was given at Capgemini Belgium](https://github.com/jekkos/android-hce-desfire/blob/master/talk/Android%20internals%20-%20Nfc%20stack%20explorations.pptx?raw=true) in 2015 to present the POC.

You can detect a phone as a Mifare Tag by using an libnfc compqatible reader with [patched libfreefare](https://github.com/jekkos/libfreefare). One working example here includes the mifare get info command, which can request some general info fields from the Android application and show them in a linux terminal. To reproduce this case it's best to use the `pn532-tamashell` binary that comes by default with libfreefare. In that case the raw command bytes for DesFire get info can be issued whcih should normally yield a valid response from the Android app.

References
----------

This project is based on the following work

* [Kevin Valk's thesis](https://github.com/kevinvalk/android-hce-framework) on HCE in Android and his work on porting JavaCard applets to the Android platform
* Original code from an [academic paper](https://securewww.esat.kuleuven.be/cosic/publications/article-2206.pdf) on [porting DesFire to JavaCard](https://github.com/Dansf/java-card-desfire-emulation). This code contains an implementation for the legacy protocols only (non AES)
* Libfreefare code which contains all the newer DesFire protocol implementation details.
