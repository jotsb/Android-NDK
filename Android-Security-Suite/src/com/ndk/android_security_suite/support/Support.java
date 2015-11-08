package com.ndk.android_security_suite.support;

public class Support {
	public static void log(String log) {
		
	}

	public static String getCPUArch() {
		String arch = android.os.Build.CPU_ABI;
		return arch;
	}
}
