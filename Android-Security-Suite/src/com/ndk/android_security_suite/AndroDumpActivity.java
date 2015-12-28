package com.ndk.android_security_suite;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.util.ArrayList;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.os.Environment;
import android.os.Handler;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewTreeObserver.OnPreDrawListener;
import android.widget.AdapterView;
import android.widget.AdapterView.OnItemClickListener;
import android.widget.ArrayAdapter;
import android.widget.ListView;

public class AndroDumpActivity extends Activity {

	private String cap_loc;
	private File cap_file;
	private ListView lv;
	private ArrayList<String> packets;
	private ArrayList<String> lv_packets;
	private ArrayAdapter<String> adapter;
	private int line_num = 0;
	private int runInterval = 500;
	private long lastKnownPosition = 0;
	private boolean tail = true;
	private RandomAccessFile readFile;

	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_andro_dump);

		lv = (ListView) this.findViewById(R.id.packets);
		packets = new ArrayList<String>();
		lv_packets = new ArrayList<String>();

		lv.setOnItemClickListener(new OnItemClickListener() {
			@Override
			public void onItemClick(AdapterView<?> myAdapter, View myView, int position, long mylng) {
				// String selectedFromList = (String)
				// (lv.getItemAtPosition(myItemInt));
				// adapter.add(myItemInt + "");

				String pkt = packets.get(position);

				Intent intent = new Intent(AndroDumpActivity.this, PacketDetailsActivity.class);
				intent.putExtra("pkt_details", pkt);
				startActivity(intent);

			}
		});

		adapter = new ArrayAdapter<String>(this, android.R.layout.simple_list_item_activated_1, lv_packets);
		lv.setAdapter(adapter);

		cap_loc = (getSdcard() + "/com.ndk.android-security-suite/capture");
		cap_file = new File(cap_loc);

		tailFile();
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

	public void tailFile() {
		final Handler handler = new Handler();
		Thread t1 = new Thread(new Runnable() {

			@Override
			public void run() {
				try {
					while (tail) {
						Thread.sleep(runInterval);
						long fileLength = cap_file.length();
						if (fileLength > lastKnownPosition) {
							readFile = new RandomAccessFile(cap_file, "r");
							readFile.seek(lastKnownPosition);

							handler.post(new Runnable() {
								@Override
								public void run() {
									String line = null;
									try {
										while ((line = readFile.readLine()) != null) {
											packets.add(line);
											processLine(line);
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
					stopRunning();
				}
			}

		});

		t1.start();
	}

	public void stopRunning() {
		tail = false;
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
						+ ") [" + pkt_len + "] Bytes ");

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

		adapter.add(pkt);
		lv.post(new Runnable() {

			@Override
			public void run() {
				lv.setSelection(adapter.getCount() - 1);
			}
		});
	}

	// private void readFile(File fin) throws IOException {
	// FileInputStream fis = new FileInputStream(fin);
	//
	// // Construct BufferedReader from InputStreamReader
	// BufferedReader br = new BufferedReader(new InputStreamReader(fis));
	//
	// String line = null;
	// while ((line = br.readLine()) != null) {
	// packets.add(line);
	// processLine(line);
	// }
	//
	// br.close();
	// }
}