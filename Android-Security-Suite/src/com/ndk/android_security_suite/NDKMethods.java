package com.ndk.android_security_suite;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.ArrayList;

import android.util.Log;

public class NDKMethods extends RootAccess {

	private final static String NDK_LOCATION = "/data/app/android-security-suite/";

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

	public static String start_capture(String filter) {
		ArrayList<String> cmds = new ArrayList<String>();
		
		if (filter == null) {
			cmds.add(NDK_LOCATION + "AndroDump");
		} else {
			cmds.add(NDK_LOCATION + "AndroDump" + " " + filter);
		}
		
		executeCommands(cmds);

		return null;
	}
	// public native static String set_msg(String text);
	//
	// static {
	// System.loadLibrary("com_example_android_ndk_example_NDKMethods");
	// }

}
