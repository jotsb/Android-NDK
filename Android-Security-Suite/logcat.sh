#!/bin/bash

#
# runs logcat and captures any exceptions logged.
#

LINE="#############################################################################"
FILE="[logcat.sh]"

clear

echo
echo "$LINE"
echo "$FILE CLEARING LOGCAT CAPTURED DATA"
echo "$LINE"
echo "$FILE adb logcat -c"
adb logcat -c
echo
sleep 1

echo "$LINE"
echo "$FILE RUNNING LOGCAT"
echo "$LINE"
echo "$FILE adb logcat -v time *:V | grep ANDROID_SECURITY_SUITE"
adb logcat -v time *:V | grep ANDROID_SECURITY_SUITE
echo

