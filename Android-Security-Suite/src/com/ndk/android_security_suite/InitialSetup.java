package com.ndk.android_security_suite;

import java.io.File;
import android.content.res.AssetManager;
import android.util.Log;

public class InitialSetup extends RootAccess {

	private final String LOG_TAG = "[ANDROID_SECURITY_SUITE] ===> ";

	AssetManager assetM = null;
	File sdCard = null;
	String arch = null;

	public InitialSetup(AssetManager am, File sdCard, String arch) {
		this.assetM = am;
		this.sdCard = sdCard;
		this.arch = arch;
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
}
