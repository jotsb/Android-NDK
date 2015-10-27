#!/bin/bash

#
# This Script is used to build NDK, move the NDK executables to res/raw/ndk directory and then run ANT to build the Android 
# Executable file
#
# Execute:  ./build.sh          (this will default to Debug Mode
#           ./build.sh debug    (this will also build the project in Debug Mode
#           ./build.sh release  (this will build project in Release Mode
#


#VARIABLES
LINE="==================================="
SCRIPT="[build.sh]"
SLEEP=1
VAR=${1}

#COMMANDS
clear

echo "$LINE"
echo "$SCRIPT CLEANING NDK PACKAGE"
echo "$LINE"
echo "$SCRIPT ndk-build clean"
echo
ndk-build clean
echo
echo
sleep $SLEEP

echo "$LINE"
echo "$SCRIPT CLEANING ANDROID PROJECT"
echo "$LINE"
echo "$SCRIPT ant clean"
echo
ant clean
echo
echo
sleep $SLEEP

echo "$LINE"
echo "$SCRIPT BUILDING NDK PACKAGE"
echo "$LINE"
echo "$SCRIPT ndk-build"
echo
ndk-build
echo
echo
sleep $SLEEP

echo "$LINE"
echo "$SCRIPT MOVING THE EXECUTABLES"
echo "$LINE"
echo "rm -fr ./assets/*"
rm -fr ./assets/*
echo "$SCRIPT cd ./libs"
cd ./libs
echo "$SCRIPT cp -r ./arm64-v8a ./armeabi ./armeabi-v7a ./mips ./mips64 ./x86 ./x86_64 ../assets"
cp -r ./arm64-v8a ./armeabi ./armeabi-v7a ./mips ./mips64 ./x86 ./x86_64 ../assets
cd ../
echo
echo
sleep $SLEEP

echo "$LINE"
echo "$SCRIPT BUILDING ANDROID PROJECT IN [ $VAR ] MODE"
echo "$LINE"
if [ -z ${var+x} ]; then 
    echo "$SCRIPT ant debug" 
    ant debug
else  
    echo "$SCRIPT ant $VAR"  
    ant "$VAR"
fi
echo
echo

echo "$LINE"
echo "$SCRIPT BUIDLING COMPLETE"
echo "$LINE"
echo "$SCRIPT [INFO] RUN ./install.sh TO INSTALL THE PROJECT ON THE DEVICE"
echo "$LINE$LINE"
