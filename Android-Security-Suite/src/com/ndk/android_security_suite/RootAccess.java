/**
 * 
 */
package com.ndk.android_security_suite;

import java.util.ArrayList;

/**
 * @author jb
 *
 */
public abstract class RootAccess {

	ArrayList<String> commands = new ArrayList<String>();

	public static boolean moveAssest(String arch, String fileName) {
		boolean retVal = false;

		return retVal;
	}

	public static boolean giveRootAccess(String filePath) {
		boolean retVal = false;

		return retVal;
	}

	public static boolean executeCommands() {
		boolean retVal = false;

		return retVal;
	}

	public void setShellCommands() {

	}

	public ArrayList<String> getCommandsToExecute() {
		return commands;
	}

}
