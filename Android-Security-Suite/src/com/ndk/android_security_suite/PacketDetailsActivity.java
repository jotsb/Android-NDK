package com.ndk.android_security_suite;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.view.Menu;
import android.view.MenuItem;
import android.widget.ArrayAdapter;
import android.widget.ListView;

public class PacketDetailsActivity extends Activity {

	private String packet;
	private String[] details;
	private ArrayAdapter<String> adapter;
	private Intent intent;
	private ListView lv;

	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_packet_details);
		intent = getIntent();
		lv = (ListView) findViewById(R.id.packet_details);

		packet = intent.getStringExtra("pkt_details");
		details = packet.split(",");
		details = format_list(details);

		adapter = new ArrayAdapter<String>(this, android.R.layout.simple_list_item_activated_1, details);
		lv.setAdapter(adapter);
	}

	public String[] format_list(String[] array) {

		for (int i = 0; i < array.length; i++) {
			String val = array[i].trim();
			if (val.equalsIgnoreCase("Ethernet Header") || val.equalsIgnoreCase("IP Header")
					|| val.equalsIgnoreCase("TCP Header") || val.equalsIgnoreCase("UDP Header")
					|| val.equalsIgnoreCase("ICMP Header") || val.equalsIgnoreCase("ARP Header")) {
				continue;
			} else {
				if (!val.isEmpty()) {
					String[] vals = val.split(":");
					val = vals[0] + "\t\t:\t\t" + vals[1];
					array[i] = "\t\t\t" + val;
				}
			}
		}
		return array;
	}

	@Override
	public boolean onCreateOptionsMenu(Menu menu) {
		// Inflate the menu; this adds items to the action bar if it is present.
		getMenuInflater().inflate(R.menu.packet_details, menu);
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
