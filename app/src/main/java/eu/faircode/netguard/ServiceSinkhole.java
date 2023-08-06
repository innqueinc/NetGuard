package eu.faircode.netguard;

import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.net.VpnService;
import android.os.Build;
import android.os.Message;
import android.os.ParcelFileDescriptor;
import android.preference.PreferenceManager;
import android.util.Log;

import androidx.core.content.ContextCompat;

import java.util.HashMap;
import java.util.Map;

public class ServiceSinkhole extends VpnService {
    private static final String TAG = "ServiceSinkhole";
    public static final String ACTION_CONNECT = "START";
    public static final String ACTION_DISCONNECT = "STOP";
    // VPN Config
    private static final String VPN_ADDRESS = "10.0.0.2"; // Only IPv4 support for now
    private static final String VPN_ROUTE = "0.0.0.0"; // default gateway
    private static final int MTU = 1500; // maximum transport unit
    // local variable
    private ParcelFileDescriptor vpn = null;
    private Thread thread;
    private Map<Integer, Forward> mapForward = new HashMap<>();


    private native long jni_init(int sdk);

    private native void jni_start(long context, int loglevel);

    private native void jni_run(long context, int tun, boolean fwd53, int rcode);

    private native void jni_stop(long context);

    private native void jni_clear(long context);

    private native int jni_get_mtu();

    private native int[] jni_get_stats(long context);

    private static native void jni_pcap(String name, int record_size, int file_size);

    private native void jni_socks5(String addr, int port, String username, String password);

    private native void jni_done(long context);

    private long jni_context = 0;

    @Override
    public void onCreate() {
        super.onCreate();
        Log.e(TAG, "onCreate: ");
        jni_context = jni_init(Build.VERSION.SDK_INT);

    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        Log.e(TAG, "onStartCommand: ");
        if (intent != null && intent.getAction() != null) {
            switch (intent.getAction()) {
                case ACTION_CONNECT:
                    build();
                    connect();
                    break;
                case ACTION_DISCONNECT:
                    disconnect();
                    break;
            }
        }
        return START_NOT_STICKY;
    }

    @Override
    public void onDestroy() {
        super.onDestroy();
        disconnect();
    }

    private void connect() {
        int prio = Log.WARN;
        jni_start(jni_context, prio);

        thread = new Thread(() -> {
            Log.e(TAG, "connect: ");
            final int rcode = 3;
            jni_run(jni_context, vpn.getFd(), mapForward.containsKey(53), rcode);

        });
        thread.start();
    }

    private void disconnect() {
        //stop running thread
        stopForeground(true);
    }

    private void build() {
        // build a vpn interface
        Builder builder = new VpnService.Builder();
        //Add a network address to the VPN interface.
        builder.addAddress(VPN_ADDRESS, 32);
        //Add a network route to the VPN interface.
        builder.addRoute(VPN_ROUTE, 0);
        //Set the maximum transmission unit (MTU) of the VPN interface.
        builder.setMtu(MTU);
        builder.setSession(getString(R.string.app_name));
        // Build configure intent
        Intent configure = new Intent(this, MainActivity.class);
        PendingIntent pi = PendingIntent.getActivity(this, 0, configure, PendingIntent.FLAG_UPDATE_CURRENT);
        builder.setConfigureIntent(pi);
        try {
            builder.addDisallowedApplication(getPackageName());
        } catch (PackageManager.NameNotFoundException e) {
            e.printStackTrace();
        }
        //build
        vpn = builder.establish();
    }
    // Called from native code
    private Allowed isAddressAllowed(Packet packet) {
        Allowed allowed = new Allowed();
        packet.allowed = true;
        return allowed;
    }
    // Called from native code
    private void accountUsage(Usage usage) {
    }
    // Called from native code
    private void nativeExit(String reason) {
        Log.e(TAG, "Native exit reason=" + reason);
    }// Called from native code
    private void nativeError(int error, String message) {
        Log.e(TAG, "Native error " + error + ": " + message);
    }

    // Called from native code
    private void logPacket(Packet packet) {

    }

    // Called from native code
    private void dnsResolved(ResourceRecord rr) {

    }

    // Called from native code
    private boolean isDomainBlocked(String name) {
        return false;
    }
    public static void start(Context context) {
        Intent intent = new Intent(context, ServiceSinkhole.class);
        intent.setAction(ACTION_CONNECT);
        ContextCompat.startForegroundService(context, intent);
    }

    public static void stop(Context context) {
        Intent intent = new Intent(context, ServiceSinkhole.class);
        intent.setAction(ACTION_DISCONNECT);
        ContextCompat.startForegroundService(context, intent);
    }
}
