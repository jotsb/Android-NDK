package com.example.android_ndk_example;

public class NDKMethods {
	public native static String set_msg(String text);

	static {
		System.loadLibrary("com_example_android_ndk_example_NDKMethods");
	}
}
