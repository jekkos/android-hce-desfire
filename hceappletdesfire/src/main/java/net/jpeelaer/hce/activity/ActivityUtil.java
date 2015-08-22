package net.jpeelaer.hce.activity;

import android.app.AlertDialog;
import android.content.Context;
import android.content.DialogInterface;
import android.os.Environment;
import android.util.Log;
import android.widget.Toast;
import net.jpeelaer.hce.R;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;

/**
 * Created by jekkos on 8/22/15.
 */
public class ActivityUtil {

    public static final String HOME_DIR = "/DesfireHce";

    private static final String LOG_TAG = ActivityUtil.class.getSimpleName();

    /**
     * Checks if external storage is available for read and write.
     * If not, show an error Toast.
     * @param context The Context in which the Toast will be shown.
     * @return True if external storage is writable. False otherwise.
     */
    public static boolean isExternalStorageWritableErrorToast(Context context) {
        if (isExternalStorageMounted()) {
            return true;
        }
        Toast.makeText(context, R.string.info_no_external_storage, Toast.LENGTH_LONG).show();
        return false;
    }

    /**
     * Check if the file already exists. If so, present a dialog to the user
     * with the options: "Replace", "Append" and "Cancel".
     * @param file File that will be written.
     * @param lines The lines to save.
     * @param isDump Set to True if file and lines are a dump file.
     * @param context The Context in which the dialog and Toast will be shown.
     * @param activity An object (most likely an Activity) that implements the
     * onSaveSuccessful() and onSaveFailure() methods. These methods will
     * be called according to the save process. Also, onSaveFailure() will
     * be called if the user hints cancel.
     */
    public static void checkFileExistenceAndSave(final java.io.File file,
                                                 final String[] lines, final boolean isDump, final Context context,
                                                 final SavableActivity activity) {
        if (file.exists()) {
            // Save conflict session file?
            int message = R.string.dialog_save_conflict_session;

            // File already exists. Replace? Append? Cancel?
            new AlertDialog.Builder(context)
                    .setTitle(R.string.dialog_save_conflict_title)
                    .setMessage(message)
                    .setIcon(android.R.drawable.ic_dialog_alert)
                    .setPositiveButton(R.string.action_replace,
                            new DialogInterface.OnClickListener() {
                                @Override
                                public void onClick(DialogInterface dialog, int which) {
                                    // Replace.
                                    if (saveFile(file, lines, false)) {
                                        Toast.makeText(context, R.string.info_save_successful,
                                                Toast.LENGTH_LONG).show();
                                        activity.onSaveSuccessful();
                                    } else {
                                        Toast.makeText(context, R.string.info_save_error,
                                                Toast.LENGTH_LONG).show();
                                        activity.onSaveFailure();
                                    }
                                }
                            })
                    .setNegativeButton(R.string.action_cancel,
                            new DialogInterface.OnClickListener() {
                                @Override
                                public void onClick(DialogInterface dialog, int id) {
                                    // Cancel.
                                    activity.onSaveFailure();
                                }
                            }).show();
        } else {
            if (saveFile(file, lines, false)) {
                Toast.makeText(context, R.string.info_save_successful,
                        Toast.LENGTH_LONG).show();
                activity.onSaveSuccessful();
            } else {
                Toast.makeText(context, R.string.info_save_error,
                        Toast.LENGTH_LONG).show();
                activity.onSaveFailure();
            }
        }
    }

    /**
     * Checks if external storage is available for read and write.
     * @return True if external storage is writable. False otherwise.
     */
    public static boolean isExternalStorageMounted() {
        return Environment.MEDIA_MOUNTED.equals(
                Environment.getExternalStorageState());
    }

    /**
     * Write an array of strings (each field is one line) to a given file.
     * @param file The file to write to.
     * @param lines The lines to save.
     * @param append Append to file (instead of replacing its content).
     * @return True if file writing was successful. False otherwise.
     */
    public static boolean saveFile(java.io.File file, String[] lines, boolean append) {
        boolean noError = true;
        if (file != null && lines != null && isExternalStorageMounted()) {
            BufferedWriter bw = null;
            try {
                bw = new BufferedWriter(new FileWriter(file, append));
                // Add new line before appending.
                if (append) {
                    bw.newLine();
                }
                int i;
                for(i = 0; i < lines.length-1; i++) {
                    bw.write(lines[i]);
                    bw.newLine();
                }
                bw.write(lines[i]);
            } catch (IOException e) {
                Log.e(LOG_TAG, "Error while writing to '"
                        + file.getName() + "' file.", e);
                noError = false;

            } finally {
                if (bw != null) {
                    try {
                        bw.close();
                    } catch (IOException e) {
                        Log.e(LOG_TAG, "Error while closing file.", e);
                        noError = false;
                    }
                }
            }
        } else {
            noError = false;
        }
        return noError;
    }
}
