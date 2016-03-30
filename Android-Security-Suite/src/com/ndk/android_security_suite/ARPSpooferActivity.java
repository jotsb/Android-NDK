package com.ndk.android_security_suite;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;

import android.app.Activity;
import android.content.Context;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.os.Bundle;
import android.os.Environment;
import android.os.Handler;
import android.text.format.Formatter;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.ProgressBar;
import android.widget.Spinner;
import android.widget.TextView;
import android.widget.Toast;

public class ARPSpooferActivity extends Activity {

	private ArrayList<String> devices;
	private ArrayAdapter<String> adapter;
	private NetworkInterface net_interface;
	private String ip_address, interface_name;
	private Thread t1;
	private boolean TAIL = true;
	private int runInterval = 500;
	private long lastKnownPosition = 0;
	private String log_file_loc;
	private File log_file;
	private RandomAccessFile readFile;

	// Accessing Views
	private Context context;
	private Button scan_btn, spoof_btn;
	private Spinner select_router, select_target;
	private ProgressBar progress_bar;
	private TextView textview1, textview2, net_interface_view, ip_address_view;

	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_arpspoofer);

		context = this.getApplicationContext();

		devices = new ArrayList<String>();

		scan_btn = (Button) findViewById(R.id.device_scan_btn);
		spoof_btn = (Button) findViewById(R.id.start_spoof_btn);
		select_router = (Spinner) findViewById(R.id.router_spinner);
		select_target = (Spinner) findViewById(R.id.target_spinner);
		progress_bar = (ProgressBar) findViewById(R.id.progressBar1);
		textview1 = (TextView) findViewById(R.id.textView1);
		textview2 = (TextView) findViewById(R.id.textView2);
		net_interface_view = (TextView) findViewById(R.id.net_interface);
		ip_address_view = (TextView) findViewById(R.id.ip_address);

		hide_views();

		adapter = new ArrayAdapter<String>(this, android.R.layout.simple_spinner_dropdown_item, devices);
		select_router.setAdapter(adapter);
		select_target.setAdapter(adapter);

		WifiManager wm = (WifiManager) getSystemService(WIFI_SERVICE);
		WifiInfo wifiInfo = wm.getConnectionInfo();
		int ip = wifiInfo.getIpAddress();
		ip_address = Formatter.formatIpAddress(ip);

		try {
			net_interface = getActiveWifiInterface(context, ip_address);
			interface_name = net_interface.getName();
		} catch (SocketException e) {
			e.printStackTrace();
		} catch (UnknownHostException e) {
			e.printStackTrace();
		}

		if (net_interface != null) {
			net_interface_view.setText(interface_name);
			ip_address_view.setText(ip_address);
		}

		scan_btn.setOnClickListener(new View.OnClickListener() {
			@Override
			public void onClick(View v) {
				TAIL = true;
				progress_bar.setVisibility(View.VISIBLE);
				NDKMethods.get_lan_devices(interface_name);
				log_file_loc = (getSdCard() + "/com.ndk.android-security-suite/arpspoof.log");
				log_file = new File(log_file_loc);
				tailFile();
			}
		});

		spoof_btn.setOnClickListener(new View.OnClickListener() {

			@Override
			public void onClick(View v) {
				String router = select_router.getSelectedItem().toString();
				String target = select_target.getSelectedItem().toString();

				Toast.makeText(context, "Router:" + router + "\nTarget:" + target, Toast.LENGTH_LONG).show();
			}
		});
	}

	public void load_devices() {
		String file_path = (getSdCard() + "/com.ndk.android-security-suite/active-devices");
		File device_list = new File(file_path);
		RandomAccessFile read_file;
		String line = null;
		try {
			read_file = new RandomAccessFile(device_list, "r");
			while ((line = read_file.readLine()) != null) {
				adapter.add(line);
			}
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	public String getSdCard() {
		String path = null;
		File location;

		location = Environment.getExternalStorageDirectory();
		path = location.getAbsolutePath();

		return path;
	}

	@Override
	public boolean onCreateOptionsMenu(Menu menu) {
		// Inflate the menu; this adds items to the action bar if it is present.
		getMenuInflater().inflate(R.menu.arpspoofer, menu);
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

	public static NetworkInterface getActiveWifiInterface(Context context, String ip_address)
			throws SocketException, UnknownHostException {
		WifiManager wifiManager = (WifiManager) context.getSystemService(Context.WIFI_SERVICE);
		// Return dynamic information about the current Wi-Fi connection, if any
		// is active.
		WifiInfo wifiInfo = wifiManager.getConnectionInfo();
		if (wifiInfo == null)
			return null;
		// InetAddress address = intToInet(wifiInfo.getIpAddress());
		InetAddress address = InetAddress.getByName(ip_address);
		return NetworkInterface.getByInetAddress(address);
	}

	public void hide_views() {
		spoof_btn.setVisibility(View.GONE);
		select_router.setVisibility(View.GONE);
		select_target.setVisibility(View.GONE);
		progress_bar.setVisibility(View.GONE);
		textview1.setVisibility(View.GONE);
		textview2.setVisibility(View.GONE);
	}

	public void scan_complete() {
		spoof_btn.setVisibility(View.VISIBLE);
		select_router.setVisibility(View.VISIBLE);
		select_target.setVisibility(View.VISIBLE);
		textview1.setVisibility(View.VISIBLE);
		textview2.setVisibility(View.VISIBLE);

		Toast.makeText(context, "Scan Complete", Toast.LENGTH_SHORT).show();
	}

	public void post_scan() {
		progress_bar.setVisibility(View.GONE);
		TAIL = false;

		load_devices();
		// adapter.sort(Collections.reverseOrder());
		scan_complete();
	}

	public void tailFile() {
		lastKnownPosition = 0;
		final Handler handler = new Handler();
		t1 = new Thread(new Runnable() {
			@Override
			public void run() {
				try {
					while (TAIL) {
						Thread.sleep(runInterval);
						long fileLength = log_file.length();
						if (fileLength > lastKnownPosition) {
							readFile = new RandomAccessFile(log_file, "r");
							readFile.seek(lastKnownPosition);
							handler.post(new Runnable() {
								@Override
								public void run() {
									String line = null;
									try {
										while ((line = readFile.readLine()) != null) {
											if (line.contains("complete")) {
												post_scan();
												break;
											}
										}
										lastKnownPosition = readFile.getFilePointer();
										readFile.close();
									} catch (IOException e) {
										e.printStackTrace();
									}
								}
							});
						}
					}
				} catch (Exception e) {
					TAIL = false;
				}
			}
		});
		t1.start();
	}
}
