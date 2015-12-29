package com.ndk.android_security_suite;

import java.util.ArrayList;

public class NDKMethods extends RootAccess {

	private final static String NDK_LOCATION = "/data/app/android-security-suite/";

	public static void start_capture(final String filter) {
		Thread t1 = new Thread(new Runnable() {
			@Override
			public void run() {
				ArrayList<String> cmds = new ArrayList<String>();
				if (filter == null || filter.trim().isEmpty()) {
					cmds.add(NDK_LOCATION + "AndroDump");
				} else {
					cmds.add(NDK_LOCATION + "AndroDump" + " -f" + filter);
				}
				executeCommands(cmds);
			}
		});
		t1.start();
	}

	public static void stop_application(final String app) {
		Thread t1 = new Thread(new Runnable() {
			@Override
			public void run() {
				ArrayList<String> cmds = new ArrayList<String>();
				if (app != null) {
					cmds.add("pkill -f " + app);
				}
				executeCommands(cmds);
			}
		});
		t1.start();
	}

	/*
	 * public static String capture() {
	 * 
	 * // String location = null; String curUid = null; java.lang.Process p;
	 * 
	 * try { // Open ROOT Shell p = Runtime.getRuntime().exec("su"); // Get
	 * Output Stream from the Shell DataOutputStream os = new
	 * DataOutputStream(p.getOutputStream()); // Get InputStream to the Shell
	 * DataInputStream is = new DataInputStream(p.getInputStream());
	 * 
	 * if (os != null && is != null) { // Request Shell's ID
	 * os.writeBytes("id\n"); os.flush();
	 * 
	 * // Read the response for the "id" command above curUid =
	 * is.readUTF().toString(); if (curUid == null) { // Request failed Log.d(
	 * "NDK Method", "Can't get root access or denied by user"); } else if
	 * (curUid .contains("uid=0") == true) { // Root access Granted
	 * 
	 * os.writeBytes("chmod -R 777 /data/data/com.example.android_ndk_example\n"
	 * );
	 * 
	 * Log.d("NDKMethod", "Root Access Granted"); } else { // Root access
	 * Rejected Log.d("NDKMethod", "Root access Rejected: " + curUid); } } }
	 * catch (IOException e) { // TODO Auto-generated catch block
	 * e.printStackTrace(); }
	 * 
	 * return curUid; }
	 */

	// public native static String set_msg(String text);
	//
	// static {
	// System.loadLibrary("com_example_android_ndk_example_NDKMethods");
	// }

}
