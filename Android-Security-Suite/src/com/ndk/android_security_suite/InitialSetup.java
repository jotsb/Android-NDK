package com.ndk.android_security_suite;

import java.io.File;
import java.io.FileNotFoundException;

import android.content.res.AssetManager;
import android.os.AsyncTask;
import android.util.Log;

public class InitialSetup extends RootAccess {

	private final String LOG_TAG = "[ANDROID_SECURITY_SUITE] ===> ";

	AssetManager assetM = null;
	File sdCard = null;
	String arch = null;
	Boolean result = false;
	String filePath = "Test";

	public InitialSetup(AssetManager am, File sdCard, String arch) {
		this.assetM = am;
		this.sdCard = sdCard;
		this.arch = arch;
	}

	public String executeSetup() {
		String[] assets = getAllAssets();

		/*
		 * try { retrieveAssetFile(assetM, sdCard, arch, "AndroDump"); filePath
		 * = moveAsset(sdCard, "AndroDump"); giveRootAccess(filePath,
		 * "AndroDump"); } catch (FileNotFoundException e) { // TODO
		 * Auto-generated catch block e.printStackTrace(); }
		 */

		ExecuteSetup es = new ExecuteSetup();
		es.execute(assets);
		return filePath;
	}

	private String[] getAllAssets() {
		String[] assets = null;
		AssetManager assetManager = assetM;
		try {
			assets = assetManager.list(arch);
		} catch (Exception e) {
			Log.e(LOG_TAG, "Failed to get List of Assets [" + e.getClass().getName() + "]", e);
		}
		return assets;
	}

	public class ExecuteSetup extends AsyncTask<String, Void, String> {

		@Override
		protected String doInBackground(String... assets) {
			String path = null;
			for (String asset : assets) {
				try {
					retrieveAssetFile(assetM, sdCard, arch, asset);
					path = moveAsset(sdCard, asset);
					giveRootAccess(path, asset);
				} catch (FileNotFoundException e) {
					Log.e(LOG_TAG, "Unable to retrieve the requested File [" + asset + "] from Assets + "
							+ e.getClass().getName(), e);
				}
			}
			return path;
		}

		@Override
		protected void onPostExecute(String result) {
			filePath = result;
		}

	}
}
