package com.ndk.android_security_suite;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import com.ndk.android_security_suite.R;
import com.ndk.android_security_suite.support.Support;

import android.app.Activity;
import android.content.res.AssetManager;
import android.os.Bundle;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.widget.TextView;
import android.widget.Toast;

public class MainActivity extends Activity {

	private String SYSTEM_ARCHITECTURE;
	private final String LOG_TAG = "ANDROID_SECURITY_SUITE";

	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_main);

		this.SYSTEM_ARCHITECTURE = Support.getCPUArch();
		Toast.makeText(getApplicationContext(), this.SYSTEM_ARCHITECTURE, Toast.LENGTH_SHORT).show();
		
		getAssetsFiles(this.SYSTEM_ARCHITECTURE, "AndroDump");

		//TextView txtview = (TextView) this.findViewById(R.id.textView1);
		//txtview.setText(getAssetsFiles(this.SYSTEM_ARCHITECTURE));

		// String ndkMessage = NDKMethods.start_capture();
		// String ndkMessage = NDKMethods.set_msg("testing");
		// TextView txtview = (TextView) this.findViewById(R.id.textView1);
		// txtview.setText(ndkMessage);
		// Toast.makeText(getApplicationContext(), ndkMessage,
		// Toast.LENGTH_LONG).show();

	}

	@Override
	public boolean onCreateOptionsMenu(Menu menu) {
		// Inflate the menu; this adds items to the action bar if it is present.
		getMenuInflater().inflate(R.menu.main, menu);
		return true;
	}

	@Override
	public boolean onOptionsItemSelected(MenuItem item) {
		// Handle action bar item clicks here. The action bar will
		// automatically handle clicks on the Home/Up button, so long
		// as you specify a parent activity in AndroidManifest.xml.
		int id = item.getItemId();
		if (id == R.id.action_settings) {
			return true;
		}
		return super.onOptionsItemSelected(item);
	}

	public void getAssetsFiles(String arhc, String filename) {
		String[] files = null;
		AssetManager assetManager = getAssets();

		try {
			files = assetManager.list("");
		} catch (IOException e) {
			Log.e(this.LOG_TAG + "getAssetsFile", "Failed to get asset files list.", e);
		}

		if (files != null) {
			for (String file : files) {
				if (file.equalsIgnoreCase(arhc)) {
					InputStream in = null;
					OutputStream out = null;
					String filePath = arhc + "/" + filename;
					Toast.makeText(getApplicationContext(), filePath, Toast.LENGTH_LONG).show();
					
					try {
						in = assetManager.open(filePath);
						File outFile = new File(getExternalFilesDir(null), filename);
						out = new FileOutputStream(outFile);
						copyFile(in, out);
					} catch (IOException e) {
						Log.e(this.LOG_TAG + "getAssetsFile", "Failed to copy asset file: " + filename, e);
					} finally {
						if (in != null) {
							try {
								in.close();
							} catch (IOException e) {
								Log.e(this.LOG_TAG + "getAssetsFile", "Failed to close the Input Stream", e);
							}
						}
						if (out != null) {
							try {
								out.close();
							} catch (IOException e) {
								Log.e(this.LOG_TAG + "getAssetsFile", "Failed to close the Output Stream", e);
							}
						}
					}
				}
			}
		}
	}

	private void copyFile(InputStream in, OutputStream out) throws IOException {
		byte[] buffer = new byte[1024];
		int read;
		while ((read = in.read(buffer)) != -1) {
			out.write(buffer, 0, read);
		}
	}
}
