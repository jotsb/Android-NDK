#!/bin/bash

#VARIABLES
LINE="==================================="
SCRIPT="[build.sh]"
NDK="/home/jb/Documents/Android/NDK/ndk/ndk-build"
SLEEP=1

#COMMANDS
clear

echo "$SCRIPT CLEANING NDK PACKAGE"
echo "$LINE"
echo "$SCRIPT ndk-build clean"
echo
$NDK clean
echo
echo
sleep $SLEEP

echo "$SCRIPT CLEANING ANDROID PROJECT"
echo "$LINE"
echo "$SCRIPT ant clean"
echo
ant clean
echo
echo
sleep $SLEEP

echo "$SCRIPT BUILDING NDK PACKAGE"
echo "$LINE"
echo "$SCRIPT ndk-build"
echo
$NDK
echo
echo
sleep $SLEEP

echo "$SCRIPT MOVING THE EXECUTABLES"
echo "$LINE"
echo "$SCRIPT cd ./libs"
cd ./libs
echo "$SCRIPT rm -f archived.zip"
rm -f archived.zip
echo "$SCRIPT zip -r archived ./arm64-v8a ./armeabi ./armeabi-v7a ./mips ./mips64 ./x86 ./x86_64"
zip -r archived ./arm64-v8a ./armeabi ./armeabi-v7a ./mips ./mips64 ./x86 ./x86_64
echo "$SCRIPT cp -v archived.zip ../res/raw/ndk/." 
cp -v archived.zip ../res/ndk/exe/.
cd ../
echo
echo
sleep $SLEEP

echo "$SCRIPT BUILDING ANDROID PROJECT"
echo "$LINE"
read -r -p "$SCRIPT Are you sure you want to build in RELEASE mode? [y/N] " response
case $response in
    [yY][eE][sS]|[yY]) 
        echo "$SCRIPT ant release"
        ant release
        ;;
    *)
        echo "$SCRIPT ant debug"
        ant debug
        ;;
esac
echo
echo

echo "$SCRIPT BUIDLING COMPLETE"
echo "$LINE"
echo "$SCRIPT [INFO] RUN ./install.sh TO INSTALL THE PROJECT ON THE DEVICE"