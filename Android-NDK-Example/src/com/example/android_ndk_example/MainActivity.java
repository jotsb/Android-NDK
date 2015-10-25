package com.example.android_ndk_example;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.widget.TextView;
import android.widget.Toast;

public class MainActivity extends Activity {

	private String SYSTEM_ARCHITECTURE;

	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_main);

		this.SYSTEM_ARCHITECTURE = this.getCPUArch();

		// String ndkMessage = NDKMethods.start_capture();
		// String ndkMessage = NDKMethods.set_msg("testing");
		// TextView txtview = (TextView) this.findViewById(R.id.textView1);
		// txtview.setText(ndkMessage);
		// Toast.makeText(getApplicationContext(), ndkMessage,
		// Toast.LENGTH_LONG).show();

	}

	public String getCPUArch() {
		String arch = android.os.Build.CPU_ABI;
		return arch;
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
}
