package com.ndk.android_security_suite;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;

import android.content.res.AssetManager;
import android.util.Log;

public abstract class RootAccess {

	private final static String LOG_TAG = "[ANDROID_SECURITY_SUITE] ===> ";
	private final static String NDK_LOCATION = "/data/app/android-security-suite/";
	ArrayList<String> commands = new ArrayList<String>();

	/**
	 * Looks for the assets files and copies a device specific executable to
	 * SDCard.
	 * 
	 * @param assetM
	 *            = reference to the Asset Manager on the device
	 * @param sdCard
	 *            = location to the where the file is copied to.
	 * @param arch
	 *            = Device Architecture type
	 * @param fileName
	 *            = Name of the executable
	 * @return
	 * @throws FileNotFoundException
	 */
	public static boolean retrieveAssetFile(AssetManager assetM, File sdCard, String arch, String fileName)
			throws FileNotFoundException {
		boolean retVal = false;
		String[] assets = null;
		InputStream in = null;
		OutputStream out = null;
		AssetManager assetManager = assetM;

		try {
			assets = assetManager.list("");

			if (assets != null) {
				for (String asset : assets) {
					if (asset.equalsIgnoreCase(arch)) {
						String filePath = arch + "/" + fileName;
						in = assetManager.open(filePath);
						File outFile = new File(sdCard, fileName);
						out = new FileOutputStream(outFile);
						retVal = copyFile(in, out);
					}
				}
			}
		} catch (IOException e) {
			Log.e(LOG_TAG + "RootAccess.retrieveAssetFile() ", "Failed to get/copy list of assets.", e);
		} catch (NullPointerException e) {
			Log.e(LOG_TAG + "RootAccess.retrieveAssetFile() ", "Unable to create a new File", e);
		} finally {
			if (in != null) {
				try {
					in.close();
				} catch (IOException e) {
					Log.e(LOG_TAG + "getAssetsFile", "Failed to close the Input Stream", e);
				}
			}
			if (out != null) {
				try {
					out.close();
				} catch (IOException e) {
					Log.e(LOG_TAG + "getAssetsFile", "Failed to close the Output Stream", e);
				}
			}
		}

		return retVal;
	}

	/**
	 * Looks for the specified file in the SDCARD and returns the absolute
	 * location of the file.
	 * 
	 * @param sdCard
	 *            = reference to the SDCARD
	 * @param fileName
	 *            = name of the file to locate.
	 * @return
	 */
	public static String moveAsset(File sdCard, String fileName) {
		String execLocation = "";
		String logFile = "";
		try {
			// File fileDir = new File(sdCard, "");
			File[] files = sdCard.listFiles();
			for (File f : files) {
				if (f.getName().equalsIgnoreCase(fileName)) {
					logFile = f.getName();
					execLocation = f.getAbsolutePath();
					break;
				}
			}
		} catch (Exception e) {
			Log.e(LOG_TAG + "RootAccess.moveAsset()", "Failed to Get the Directory Listing", e);
		}
		Log.e(LOG_TAG, "Asset Location: " + execLocation + " Asset Name: " + logFile);
		return execLocation;
	}

	/**
	 * Moves the executable and gives it ROOT Access
	 * 
	 * @param filePath
	 * @param fileName
	 * @return
	 */
	public static boolean giveRootAccess(String filePath, String fileName) {
		boolean retVal = false;
		boolean exitSu = false;
		java.lang.Process suProcess;

		try {
			suProcess = Runtime.getRuntime().exec("su");
			DataOutputStream executeCmd = new DataOutputStream(suProcess.getOutputStream());
			DataInputStream cmdOutput = new DataInputStream(suProcess.getInputStream());

			if (executeCmd != null && cmdOutput != null) {
				executeCmd.writeBytes("id\n");
				executeCmd.flush();
				String curUid = cmdOutput.readLine();
				if (curUid == null) {
					Log.e(LOG_TAG, "Can't get ROOT Access or Denied by User");
				} else if (curUid.contains("uid=0")) {
					Log.e(LOG_TAG, "ROOT Access Granted: " + curUid);
					executeCmd.writeBytes("mkdir " + NDK_LOCATION + "\n");
					executeCmd.flush();

					executeCmd.writeBytes("mv " + filePath + " " + NDK_LOCATION + "\n");
					executeCmd.flush();
					Log.e(LOG_TAG, "Executable Successfully moved to " + NDK_LOCATION + " directory");

					executeCmd.writeBytes("chown -v root " + NDK_LOCATION + fileName + "\n");
					executeCmd.flush();
					retVal = true;
					Log.e(LOG_TAG, "ROOT Permission Granted");

					executeCmd.writeBytes("chmod 775 " + NDK_LOCATION + fileName + "\n");
					executeCmd.flush();
					Log.e(LOG_TAG, "Execute permissions given to the Executable");

					exitSu = true;
				} else {
					exitSu = true;
					Log.e(LOG_TAG, "ROOT Access Rejected: " + curUid);
				}

				if (exitSu) {
					executeCmd.writeBytes("exit\n");
					executeCmd.flush();
				}
			}

		} catch (Exception e) {
			retVal = false;
			Log.e(LOG_TAG + "moveToBin()", "Unable to move the file [" + e.getClass().getName() + "] : ", e);
		}

		return retVal;
	}

	/**
	 * Method used to run multiple Shell Commands at once.
	 * 
	 * @param cmd
	 *            = takes in a list of functions in the format of ArrayList.
	 * @return
	 */
	public static boolean executeCommands(ArrayList<String> cmd) {
		boolean retVal = false;

		try {
			ArrayList<String> commands = cmd;
			if (commands != null && commands.size() > 0) {
				Process suProcess = Runtime.getRuntime().exec("su");
				DataOutputStream os = new DataOutputStream(suProcess.getOutputStream());

				for (String currCmd : commands) {
					os.writeBytes(currCmd + "\n");
					os.flush();
				}
				try {
					int suProcessReturnVal = suProcess.waitFor();
					if (suProcessReturnVal != 255) {
						retVal = true;
					} else {
						retVal = false;
					}
				} catch (Exception e) {
					Log.e(LOG_TAG, "Error executing root action [" + e.getClass().getName() + "]", e);
				}
			}
		} catch (Exception e) {
			Log.e(LOG_TAG, "Error Executing ROOT Commands [" + e.getClass().getName() + "] : ", e);
		}
		return retVal;
	}

	/**
	 * Copy files from one location to another
	 * 
	 * @param in
	 *            Input Stream from where the file is copied from
	 * @param out
	 *            Output Stream to the location the file is copied to
	 * 
	 * @return status status of whether the copy succeeded or failed
	 * @throws IOException
	 */
	private static boolean copyFile(InputStream in, OutputStream out) throws IOException {
		byte[] buffer = new byte[1024];
		int read;
		boolean status = false;
		try {
			while ((read = in.read(buffer)) != -1) {
				out.write(buffer, 0, read);
			}
			status = true;
		} catch (IOException e) {
			status = false;
			Log.e(LOG_TAG + "RootAccess.copyFile()", "Unable a to copy the files to the SDCARD", e);
		}

		return status;
	}

	/*
	 * public void setShellCommands() {
	 * 
	 * }
	 */

	// public abstract ArrayList<String> getCommandsToExecute();
}
