#!/bin/bash

#
# This script is used to install the Project on the Device and then Run it.
#

FILE="[install.sh]"
LINE="======================================================================"

#clear

echo "$LINE"
echo "$FILE UNINSTALLING com.example.android_ndk_example APPLICATION"
echo "$LINE"
echo "$FILE adb uninstall com.example.android_ndk_example"
adb uninstall com.example.android_ndk_example
echo "$FILE UNINSTALL COMPLETE"
echo

echo "$LINE"
echo "$FILE INSTALLING AndroidNDK-debug.apk"
echo "$LINE"
echo "$FILE adb -d install -r ./bin/AndroidNDK-debug.apk"
adb -d install -r ./bin/AndroidNDK-debug.apk
echo "$FILE INSTALLATION COMPLETE"
echo

echo "$LINE"
echo "$FILE RUNNING AndroidNDK APPLICATION"
echo "$LINE"
echo "$FILE adb shell am start -a android.intent.action.Main -n com.example.android_ndk_example/.MainActivity"
adb shell am start -a android.intent.action.Main -n com.example.android_ndk_example/.MainActivity
echo "$FILE APPLICATION RUNNING"
echo
