package com.ndk.android_security_suite;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;

import android.app.Activity;
import android.content.Context;
import android.os.Bundle;
import android.os.Environment;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ArrayAdapter;
import android.widget.BaseAdapter;
import android.widget.ListView;
import android.widget.SectionIndexer;

public class AndroDumpActivity extends Activity {

	private String cap_loc;
	private File cap_file;
	private ListView lv;
	private ArrayList<String> packets;
	private ArrayList<String> lv_packets;
	private ArrayAdapter<String> adapter;
	private int line_num = 0;

	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_andro_dump);

		lv = (ListView) this.findViewById(R.id.packets);
		packets = new ArrayList<String>();
		lv_packets = new ArrayList<String>();

		adapter = new ArrayAdapter<String>(this, android.R.layout.simple_list_item_single_choice, lv_packets);
		lv.setAdapter(adapter);

		cap_loc = (getSdcard() + "/com.ndk.android-security-suite/capture");
		cap_file = new File(cap_loc);

		try {
			readFile(cap_file);
			// processLineByLine(cap_file);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	@Override
	public boolean onCreateOptionsMenu(Menu menu) {
		// Inflate the menu; this adds items to the action bar if it is present.
		getMenuInflater().inflate(R.menu.andro_dump, menu);
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

	public String getSdcard() {
		String path = null;
		File location;

		location = Environment.getExternalStorageDirectory();
		path = location.getAbsolutePath();

		return path;
	}

	private void readFile(File fin) throws IOException {
		FileInputStream fis = new FileInputStream(fin);

		// Construct BufferedReader from InputStreamReader
		BufferedReader br = new BufferedReader(new InputStreamReader(fis));

		String line = null;
		while ((line = br.readLine()) != null) {
			packets.add(line);
			processLine(line);
		}

		br.close();
	}

	private void processLine(String aline) {
		String pkt = null;
		String src_ip = null, src_port = null, dest_ip = null, dest_port = null, protocol = null, pkt_len = null;
		String[] header = aline.split(",");

		line_num++;

		if (header[3].contains("IP")) {
			src_ip = header[12].split(":")[1];
			dest_ip = header[13].split(":")[1];
			protocol = header[14].split(":")[1];
			pkt_len = header[8].split(":")[1].replaceAll("\\D+", "");

			if (protocol.contains("TCP")) {
				src_port = header[16].split(":")[1];
				dest_port = header[17].split(":")[1];

				pkt = (line_num + ": " + src_ip + ":" + src_port + " > " + dest_ip + ":" + dest_port + " (" + protocol
						+ ""
						+ "0 [" + pkt_len + "] Bytes ");
				
			} else if (protocol.contains("UDP")) {
				src_port = header[16].split(":")[1];
				dest_port = header[17].split(":")[1];

				pkt = (line_num + ": " + src_ip + ":" + src_port + " > " + dest_ip + ":" + dest_port + " (" + protocol
						+ ") [" + pkt_len + "] Bytes ");
				
			} else if (protocol.contains("ICMP")) {
				String type = header[16].split(":")[1];
				pkt = (line_num + ": " + src_ip + " > " + dest_ip + " (" + protocol + ")  [" + pkt_len + "] Bytes "
						+ type);
			}
		} else if (header[3].contains("ARP")) {
			src_ip = header[10].split(":")[1];
			dest_ip = header[11].split(":")[1];
			protocol = header[6].split(":")[1];
			String operation = header[7].split(":")[1];
			
			pkt = (line_num + ": " + src_ip + " > " + dest_ip + " (" + protocol + ") " + operation);
		}

		lv_packets.add(pkt);
	}
}

class CustomListAdapter extends BaseAdapter implements SectionIndexer {

	Context ctx = null;

	public CustomListAdapter(Context ctx) {
		this.ctx = ctx;
	}

	@Override
	public int getCount() {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	public Object getItem(int position) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public long getItemId(int position) {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	public View getView(int position, View convertView, ViewGroup parent) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Object[] getSections() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public int getPositionForSection(int sectionIndex) {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	public int getSectionForPosition(int position) {
		// TODO Auto-generated method stub
		return 0;
	}

}
