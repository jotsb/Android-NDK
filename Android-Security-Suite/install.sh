#!/bin/bash

#
# This script is used to install the Project on the Device and then Run it.
#
# Execute:	./install.sh debug    (this will also build the project in Debug Mode
#           ./install.sh release  (this will build project in Release Mode


FILE="[install.sh]"
LINE="======================================================================"
VAR=${1}
SLEEP=1

clear

echo
echo "$LINE"
echo "$FILE CLEANING ANDROID PROJECT"
echo "$LINE"
echo "$FILE ant clean"
echo
ant clean
echo
echo
sleep $SLEEP


echo "$LINE"
echo "$FILE BUILDING ANDROID PROJECT IN [ $VAR ] MODE"
echo "$LINE"
if [ -z ${VAR+x} ]; then
    echo "$FILE ant debug"
    ant debug
else
    echo "$FILE ant $VAR"
    ant "$VAR"
fi
echo
echo
sleep $SLEEP


echo "$LINE"
echo "$FILE UNINSTALLING com.example.android_security_suite APPLICATION"
echo "$LINE"
echo "$FILE adb uninstall com.example.android_security_suite"
adb uninstall com.example.android_security_suite
echo "$FILE UNINSTALL COMPLETE"
echo
sleep $SLEEP


echo "$LINE"
echo "$FILE INSTALLING AndroidNDK-debug.apk"
echo "$LINE"
echo "$FILE adb -d install -r ./bin/AndroidNDK-debug.apk"
adb -d install -r ./bin/AndroidNDK-debug.apk
echo "$FILE INSTALLATION COMPLETE"
echo
sleep $SLEEP


echo "$LINE"
echo "$FILE RUNNING AndroidNDK APPLICATION"
echo "$LINE"
echo "$FILE adb shell am start -a android.intent.action.Main -n com.example.android_security_suite/.MainActivity"
adb shell am start -a android.intent.action.Main -n com.example.android_security_suite/.MainActivity
echo "$FILE APPLICATION RUNNING"
echo
echo
