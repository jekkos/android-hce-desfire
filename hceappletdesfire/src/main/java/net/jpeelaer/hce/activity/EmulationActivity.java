package net.jpeelaer.hce.activity;


import android.app.Activity;
import android.app.AlertDialog;
import android.app.PendingIntent;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.IntentFilter;
import android.graphics.Color;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.os.*;
import android.os.PowerManager.WakeLock;
import android.text.InputType;
import android.text.Spannable;
import android.text.style.ForegroundColorSpan;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.view.Window;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;
import net.jpeelaer.hce.R;
import net.jpeelaer.hce.desfire.DesFireInstruction;
import net.jpeelaer.hce.desfire.DesfireApplet;
import org.kevinvalk.hce.framework.AppletThread;
import org.kevinvalk.hce.framework.HceFramework;
import org.kevinvalk.hce.framework.TagWrapper;
import org.kevinvalk.hce.framework.apdu.Apdu;
import org.kevinvalk.hce.framework.apdu.CommandApdu;
import org.yaml.snakeyaml.Yaml;

import javax.crypto.NoSuchPaddingException;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.GregorianCalendar;
import java.util.List;
import java.util.Locale;

public class EmulationActivity extends Activity implements SavableActivity {

    public static final String TECH_ISO_PCDA = "android.nfc.tech.IsoPcdA";

    private static final int FILE_CHOOSER_DUMP_FILE = 1;

    private static final String TAG = EmulationActivity.class.getSimpleName();

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
    private String sessionName;


    private final PropertyChangeListener APDU_LISTENER = new PropertyChangeListener() {

        @Override
        public void propertyChange(PropertyChangeEvent event) {
            if (AppletThread.LAST_APDUS.equals(event.getPropertyName())) {
                publishApdu((Apdu[]) event.getNewValue(), event.getPropertyName());
            } else if (AppletThread.LAST_ERROR.equals(event.getPropertyName())) {
                publishError((Exception) event.getNewValue());
            }
        }

    };

    private void initFramework() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException,
		NoSuchPaddingException, InvalidKeySpecException
	{
		if (desfireApplet == null) {
			desfireApplet = new DesfireApplet();
		}
		
		// Enable NFC HCE and register our appletsAF
		if (framework == null) {
			framework = new HceFramework(APDU_LISTENER);
        }
		framework.register(desfireApplet);
	}

    /**
     * Add a menu with "preferences", "about", etc. to the Activity.
     */
    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.main_functions, menu);
        return true;
    }

    private void publishError(Exception e) {
        publishMessage(e.getMessage(), R.color.red);
    }

    private void publishMessage(final String message, final int color) {
        Handler handler = new Handler(Looper.getMainLooper());
        handler.post(new Runnable() {

            @Override
            public void run() {
                TextView tv = (TextView) findViewById(R.id.apduView);
                appendColoredText(tv, message, color);
            }
        });
    }

    private  void publishApdu(final Apdu[] apdus, final String apduType) {
        Handler handler = new Handler(Looper.getMainLooper());
        handler.post(new Runnable() {

            @Override
            public void run() {
                TextView tv = (TextView) findViewById(R.id.apduView);
                for (Apdu apdu : apdus) {
                    String s = String.valueOf(apdu.getBuffer());
                    boolean isCommandApdu = Apdu.COMMAND_APDU.equals(apduType);

                    if (isCommandApdu) {
                        CommandApdu commandApdu = (CommandApdu) apdu;
                        DesFireInstruction desFireInstruction = DesFireInstruction.parseInstruction(commandApdu.ins);
                        appendColoredText(tv, " *** " + desFireInstruction.name() + " ***", R.color.yellow);
                    }
                    String prefix = isCommandApdu ? "--> " : "<-- ";
                    String text = prefix + " " + s;
                    appendColoredText(tv, text, isCommandApdu ? R.color.dark_green : R.color.orange);
                }

            }
        });
    }

    public void appendColoredText(TextView tv, String text, int color) {
        int start = tv.getText().length();
        tv.append(text + System.getProperty("line.separator"));
        int end = tv.getText().length();
        Spannable spannableText = (Spannable) tv.getText();
        ForegroundColorSpan foregroundColorSpan = new ForegroundColorSpan(getResources().getColor(color));
        spannableText.setSpan(foregroundColorSpan, start, end,  Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);
    }

    /**
     * Handle the selected function from the editor menu.
     * @see #saveSession()
     */
    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        // Handle item selection.
        switch (item.getItemId()) {
            case R.id.menuSessionEditorSave:
                saveSession();
                return true;
            case R.id.menuSessionEditorLoad:
                loadSession();
                return true;
        }
        return false;
    }

    /**
     * if file chooser result is O.K.
     */
    @Override
    public void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);

        switch (requestCode) {
            case FILE_CHOOSER_DUMP_FILE:
                if (resultCode == Activity.RESULT_OK) {
                    // reload this screen with data contained in yaml file
                }
                break;
        }
    }

    private void loadSession() {
        // send out activity.. fetch result back
        Intent intent = new Intent(this, FileChooserActivity.class);
        intent.putExtra(FileChooserActivity.EXTRA_DIR, ActivityUtil.HOME_DIR);
        intent.putExtra(FileChooserActivity.EXTRA_TITLE,
                getString(R.string.text_open_session_title));
        intent.putExtra(FileChooserActivity.EXTRA_BUTTON_TEXT,
                getString(R.string.action_open_dump_file));
        intent.putExtra(FileChooserActivity.EXTRA_ENABLE_DELETE_FILE, true);
        startActivityForResult(intent, FILE_CHOOSER_DUMP_FILE);
    }

    /**
     * Check if it is a valid session file ,
     * create a file name suggestion and call
     * {@link #saveFile(String[], String, boolean, int, int)}.
     * @see #saveFile(String[], String, boolean, int, int)
     */
    private void saveSession() {
        // Set a filename (Date + Time) if there is none.
        if (sessionName == null) {
            GregorianCalendar calendar = new GregorianCalendar();
            SimpleDateFormat fmt = new SimpleDateFormat("yyyy-MM-dd_HH-mm-ss",
                    Locale.getDefault());
            fmt.setCalendar(calendar);
            String dateFormatted = fmt.format(calendar.getTime());
            sessionName = "Session-" + dateFormatted;
        }

        Yaml yamlFile = new Yaml();
        String dump = yamlFile.dump(desfireApplet.getMasterFile());
        saveFile(dump.split(System.getProperty("line.separator")), sessionName, true, R.string.dialog_save_session_title,
                R.string.dialog_save_session);
    }

    /**
     * Check if the external storage is writable
     * {@link ActivityUtil#isExternalStorageWritableErrorToast(Context)},
     * ask user for a save name and then call
     * {@link ActivityUtil#checkFileExistenceAndSave(java.io.File, String[], boolean,
     * Context, SavableActivity)}.
     * @param data Data to save.
     * @param fileName Name of the file.
     * @param isDump True if data contains a dump. False if data contains keys.
     * @param titleId Resource ID for the title of the dialog.
     * @param messageId Resource ID for the message of the dialog.
     * @see ActivityUtil#isExternalStorageWritableErrorToast(Context)
     */
    private void saveFile(final String[] data, final String fileName,
                          final boolean isDump, int titleId, int messageId) {
        if (!ActivityUtil.isExternalStorageWritableErrorToast(this)) {
            return;
        }
        final java.io.File path = Environment.getExternalStoragePublicDirectory(ActivityUtil.HOME_DIR);
        final Context context = this;

        // Ask user for filename.
        final EditText input = new EditText(this);
        input.setInputType(InputType.TYPE_CLASS_TEXT);
        input.setLines(1);
        input.setHorizontallyScrolling(true);
        input.setText(fileName);
        input.setSelection(input.getText().length());
        new AlertDialog.Builder(this)
                .setTitle(titleId)
                .setMessage(messageId)
                .setIcon(android.R.drawable.ic_menu_save)
                .setView(input)
                .setPositiveButton(R.string.action_save,
                        new DialogInterface.OnClickListener() {
                            @Override
                            public void onClick(DialogInterface dialog, int whichButton) {
                                if (input.getText() != null
                                        && !input.getText().toString().equals("")) {
                                    java.io.File file = new java.io.File(path.getPath(),
                                            input.getText().toString());
                                    ActivityUtil.checkFileExistenceAndSave(file, data,
                                            isDump, context, EmulationActivity.this);
                                    sessionName = file.getName();
                                } else {
                                    // Empty name is not allowed.
                                    Toast.makeText(context, R.string.info_empty_file_name,
                                            Toast.LENGTH_LONG).show();
                                }
                            }
                        })
                .setNegativeButton(R.string.action_cancel,
                        new DialogInterface.OnClickListener() {
                            @Override
                            public void onClick(DialogInterface dialog, int whichButton) { }
                        }).show();
    }


    @Override
	protected void onCreate(Bundle savedInstanceState)
	{
		requestWindowFeature(Window.FEATURE_INDETERMINATE_PROGRESS);
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_main);

        // Get power management
        powerManager = (PowerManager) getSystemService(Context.POWER_SERVICE);
        
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

            publishMessage("Desfire emulator ready", Color.WHITE);
            publishMessage("Waiting for nfc initiate", Color.WHITE);

            // Force intent
            Intent intent = getIntent();
            String action = intent.getAction();
            if (NfcAdapter.ACTION_TECH_DISCOVERED.equals(action))
                handleTag(intent);
        } catch(Exception e) {
            publishError(e);
        	Log.e(TAG, "Failed to initialize applet", e);
        }
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
        
		if (adapter != null) {
            adapter.enableForegroundDispatch(this, pendingIntent, filters, techLists);
        }
	}
    
    @Override
    public void onPause()
	{
		super.onPause();
		if (adapter != null) {
            adapter.disableForegroundDispatch(this);
        }

        if (wakeLock != null) {
            wakeLock.release();
        }
	}

    @Override
    public void onSaveSuccessful() {
        finish();
    }

    @Override
    public void onSaveFailure() {    }

}
