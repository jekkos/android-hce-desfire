package net.jpeelaer.hce.desfire;


import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.PowerManager;
import android.os.PowerManager.WakeLock;
import android.support.v4.app.FragmentActivity;
import android.text.method.ScrollingMovementMethod;
import android.util.Log;
import android.view.Menu;
import android.view.Window;
import android.widget.TextView;
import org.kevinvalk.hce.R;
import org.kevinvalk.hce.framework.HceFramework;
import org.kevinvalk.hce.framework.TagWrapper;

import javax.crypto.NoSuchPaddingException;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.List;

public class EmulationActivity extends FragmentActivity {

	// NFC HCE
	private DesfireApplet desfireApplet = null;
	private HceFramework framework = null;
	
	// Settings
	private NfcAdapter adapter;
    private PendingIntent pendingIntent;
    private IntentFilter[] filters;
    private String[][] techLists;
    private WakeLock wakeLock;
    private PowerManager powerManager;
	public static final String TECH_ISO_PCDA = "android.nfc.tech.IsoPcdA";
	//private static final String TECH_ISO_A = "android.nfc.tech.NfcA";
	
	private static final String TAG = "HCE";
	/**
	 * The serialization (saved instance state) Bundle key representing the
	 * current dropdown position.
	 */
	private static final String STATE_SELECTED_NAVIGATION_ITEM = "selected_navigation_item";
	
	private void initFramework() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, 
		NoSuchPaddingException, InvalidKeySpecException
	{
		if (desfireApplet == null) {
			desfireApplet = new DesfireApplet();
		}
		
		// Enable NFC HCE and register our appletsAF
		if (framework == null)
			framework = new HceFramework();
		framework.register(desfireApplet);
	}

	@Override
	protected void onCreate(Bundle savedInstanceState)
	{
		requestWindowFeature(Window.FEATURE_INDETERMINATE_PROGRESS);
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_main);

        // Get power management
        powerManager = (PowerManager) getSystemService(Context.POWER_SERVICE);
        
		// Set up the action bar to show a dropdown list.
		startTextViewLog();
        // Fix adapter settings
        adapter = NfcAdapter.getDefaultAdapter(this);
        adapter.setNdefPushMessage(null, this);
        if (Build.VERSION.SDK_INT > Build.VERSION_CODES.JELLY_BEAN)
            adapter.setBeamPushUris(null, this);
        
        try {
            // Setup our framework
            initFramework();
            
            // Register new tech
            pendingIntent = PendingIntent.getActivity(this, 0, new Intent(this, getClass()).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP), 0);
            filters = new IntentFilter[] {new IntentFilter(NfcAdapter.ACTION_TECH_DISCOVERED)};
            techLists = new String[][] { { TECH_ISO_PCDA} };
            
            // Force intent
            Intent intent = getIntent();
            String action = intent.getAction();
            if (NfcAdapter.ACTION_TECH_DISCOVERED.equals(action))
                handleTag(intent);
        } catch(Exception e) {
        	Log.e(TAG, "Failed to initialize applet", e);
        }
	}

	private void startTextViewLog() {
	    final Handler handler = new Handler();
		  // Do something long
	    Runnable runnable = new Runnable() {
	        @Override
	        public void run() {
	            //do long stuff (like getting info for intent)
	            handler.post(new Runnable() {
	            @Override
	            public void run() {
	            	//start new actiity with intent you just made
	            	//Do something that takes a while
	            		TextView tv = (TextView)findViewById(R.id.apduView);
	            		tv.setMovementMethod(new ScrollingMovementMethod());
						// TODO update apduView here with command/response buffer (apdu's will be saved as enum?)
	            }
	        });
	        }
	    };
	    new Thread(runnable).start();
	}
	
    @Override
    public void onNewIntent(Intent intent)
    {
        handleTag(intent);
    }
    
    private void handleTag(Intent intent)
    {       
        try {
            Tag tag = null;
            if (intent.getExtras() != null) {
                tag = (Tag) intent.getExtras().get(NfcAdapter.EXTRA_TAG);
            }
            if (tag == null)
            {
                return;
            }
            
            
            List<String> techList = Arrays.asList(tag.getTechList());
            if (!techList.contains(TECH_ISO_PCDA)) {
                return;
            }

            TagWrapper tw = new TagWrapper(tag, TECH_ISO_PCDA);
            if (!tw.isConnected())
                tw.connect();
            
            // Let the framework handle the tag
            if (! framework.handleTag(tw))
            {
            	Log.w(TAG, "Failed to handle the tag");
            }
            
        }
        catch (Exception e)
        {
            throw new RuntimeException(e);
        }
    }

    @SuppressWarnings("deprecation")
	@Override
	public void onResume()
	{
    	super.onResume();
    	
		wakeLock = powerManager.newWakeLock(PowerManager.SCREEN_DIM_WAKE_LOCK, getString(R.string.app_name));
        wakeLock.acquire();
        
		if (adapter != null)
			adapter.enableForegroundDispatch(this, pendingIntent, filters, techLists);
	}
    
    @Override
    public void onPause()
	{
		super.onPause();
		if (adapter != null)
			adapter.disableForegroundDispatch(this);
		
        if (wakeLock != null)
            wakeLock.release();
	}
    
}
