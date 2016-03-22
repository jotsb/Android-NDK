package com.ndk.android_security_suite;

import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;

import android.app.Activity;
import android.content.Context;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.os.Bundle;
import android.text.format.Formatter;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.ListView;
import android.widget.ProgressBar;
import android.widget.Spinner;
import android.widget.TextView;

public class ARPSpooferActivity extends Activity {

	private ArrayList<String> packets;
	private ArrayList<String> lv_packets;
	private ArrayAdapter<String> adapter;
	private NetworkInterface net_interface;
	private String ip_address;
	private Context context;

	// Accessing Views
	private Button scan_btn, spoof_btn;
	private Spinner select_router, select_target;
	private ProgressBar progress_bar;
	private TextView textview1, textview2, net_interface_view, ip_address_view;

	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_arpspoofer);

		context = this.getApplicationContext();

		packets = new ArrayList<String>();
		lv_packets = new ArrayList<String>();

		scan_btn = (Button) findViewById(R.id.device_scan_btn);
		spoof_btn = (Button) findViewById(R.id.start_spoof_btn);
		select_router = (Spinner) findViewById(R.id.router_spinner);
		select_target = (Spinner) findViewById(R.id.target_spinner);
		progress_bar = (ProgressBar) findViewById(R.id.progressBar1);
		textview1 = (TextView) findViewById(R.id.textView1);
		textview2 = (TextView) findViewById(R.id.textView2);
		net_interface_view = (TextView) findViewById(R.id.net_interface);
		ip_address_view = (TextView) findViewById(R.id.ip_address);

		WifiManager wm = (WifiManager) getSystemService(WIFI_SERVICE);
		WifiInfo wifiInfo = wm.getConnectionInfo();
		int ip = wifiInfo.getIpAddress();
		ip_address = Formatter.formatIpAddress(ip);

		spoof_btn.setVisibility(View.GONE);
		select_router.setVisibility(View.GONE);
		select_target.setVisibility(View.GONE);
		progress_bar.setVisibility(View.GONE);
		textview1.setVisibility(View.GONE);
		textview2.setVisibility(View.GONE);

		try {
			net_interface = getActiveWifiInterface(context, ip_address);
		} catch (SocketException e) {
			e.printStackTrace();
		} catch (UnknownHostException e) {
			e.printStackTrace();
		}

		if (net_interface != null) {
			net_interface_view.setText(net_interface.getName());
			ip_address_view.setText(ip_address);
		}

		scan_btn.setOnClickListener(new View.OnClickListener() {
			@Override
			public void onClick(View v) {

				progress_bar.setVisibility(View.VISIBLE);
				
			}
		});
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
}
