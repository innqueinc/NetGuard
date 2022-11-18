package eu.faircode.netguard;


import android.app.Notification;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import android.preference.PreferenceManager;
import android.text.TextUtils;
import android.util.Log;
import android.util.TypedValue;

import androidx.core.app.NotificationCompat;
import androidx.core.app.NotificationManagerCompat;
import androidx.core.content.ContextCompat;

import java.io.IOException;
import java.math.BigInteger;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InterfaceAddress;
import java.net.NetworkInterface;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.locks.ReentrantReadWriteLock;


public class ServiceSinkhole extends VpnService {
    private static final String TAG = "NetGuard.Service";

    private boolean last_connected = false;
    private boolean last_metered = true;
    private boolean last_interactive = false;
    private int last_allowed = -1;
    private int last_blocked = -1;
    private int last_hosts = -1;
    private long jni_context = 0;
    private Thread tunnelThread = null;
    private Builder last_builder = null;
    private ParcelFileDescriptor vpn = null;
    private Map<String, Boolean> mapHostsBlocked = new HashMap<>();
    private Map<Integer, Boolean> mapUidAllowed = new HashMap<>();
    private Map<Integer, Integer> mapUidKnown = new HashMap<>();
    private Map<Integer, Forward> mapForward = new HashMap<>();
    private Map<Integer, Boolean> mapNotify = new HashMap<>();
    private ReentrantReadWriteLock lock = new ReentrantReadWriteLock(true);
    private static final int NOTIFY_ENFORCING = 1;
    private static final int NOTIFY_ERROR = 5;
    public static final String EXTRA_COMMAND = "Command";
    private static final String EXTRA_REASON = "Reason";
    public static final String EXTRA_INTERACTIVE = "Interactive";
    public static final String EXTRA_TEMPORARY = "Temporary";
    private native long jni_init(int sdk);
    private native void jni_start(long context, int loglevel);
    private native void jni_run(long context, int tun, boolean fwd53, int rcode);
    private native void jni_stop(long context);
    private native void jni_clear(long context);
    private native int jni_get_mtu();
    private native void jni_done(long context);

    private void start() {
        if (vpn == null) {
            startForeground(NOTIFY_ENFORCING, getEnforcingNotification(-1, -1, -1));
            List<Rule> listRule = Rule.getRules(true, ServiceSinkhole.this);
            List<Rule> listAllowed = getAllowedRules(listRule);
            last_builder = getBuilder(listAllowed, listRule);
            vpn = startVPN(last_builder);
            startNative(vpn, listAllowed, listRule);
            updateEnforcingNotification(listAllowed.size(), listRule.size());
        }
    }

    public static List<InetAddress> getDns(Context context) {
        List<InetAddress> listDns = new ArrayList<>();
        List<String> sysDns = Util.getDefaultDNS(context);

        // Get custom DNS servers
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(context);
        boolean ip6 = prefs.getBoolean("ip6", true);
        String vpnDns1 = prefs.getString("dns", null);
        String vpnDns2 = prefs.getString("dns2", null);
        Log.i(TAG, "DNS system=" + TextUtils.join(",", sysDns) + " VPN1=" + vpnDns1 + " VPN2=" + vpnDns2);

        if (vpnDns1 != null) try {
            InetAddress dns = InetAddress.getByName(vpnDns1);
            if (!(dns.isLoopbackAddress() || dns.isAnyLocalAddress()) && (ip6 || dns instanceof Inet4Address))
                listDns.add(dns);
        } catch (Throwable ignored) {
        }

        if (vpnDns2 != null) try {
            InetAddress dns = InetAddress.getByName(vpnDns2);
            if (!(dns.isLoopbackAddress() || dns.isAnyLocalAddress()) && (ip6 || dns instanceof Inet4Address))
                listDns.add(dns);
        } catch (Throwable ex) {
            Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
        }

        // Use system DNS servers only when no two custom DNS servers specified
        if (listDns.size() <= 1) for (String def_dns : sysDns)
            try {
                InetAddress ddns = InetAddress.getByName(def_dns);
                if (!listDns.contains(ddns) && !(ddns.isLoopbackAddress() || ddns.isAnyLocalAddress()) && (ip6 || ddns instanceof Inet4Address))
                    listDns.add(ddns);
            } catch (Throwable ex) {
                Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
            }

        // Remove local DNS servers when not routing LAN
        boolean lan = prefs.getBoolean("lan", false);
        boolean use_hosts = prefs.getBoolean("filter", false) && prefs.getBoolean("use_hosts", false);
        if (lan && use_hosts) {
            List<InetAddress> listLocal = new ArrayList<>();
            try {
                Enumeration<NetworkInterface> nis = NetworkInterface.getNetworkInterfaces();
                if (nis != null) while (nis.hasMoreElements()) {
                    NetworkInterface ni = nis.nextElement();
                    if (ni != null && ni.isUp() && !ni.isLoopback()) {
                        List<InterfaceAddress> ias = ni.getInterfaceAddresses();
                        if (ias != null) for (InterfaceAddress ia : ias) {
                            InetAddress hostAddress = ia.getAddress();
                            BigInteger host = new BigInteger(1, hostAddress.getAddress());

                            int prefix = ia.getNetworkPrefixLength();
                            BigInteger mask = BigInteger.valueOf(-1).shiftLeft(hostAddress.getAddress().length * 8 - prefix);

                            for (InetAddress dns : listDns)
                                if (hostAddress.getAddress().length == dns.getAddress().length) {
                                    BigInteger ip = new BigInteger(1, dns.getAddress());

                                    if (host.and(mask).equals(ip.and(mask))) {
                                        Log.i(TAG, "Local DNS server host=" + hostAddress + "/" + prefix + " dns=" + dns);
                                        listLocal.add(dns);
                                    }
                                }
                        }
                    }
                }
            } catch (Throwable ex) {
                Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
            }

            List<InetAddress> listDns4 = new ArrayList<>();
            List<InetAddress> listDns6 = new ArrayList<>();
            try {
                listDns4.add(InetAddress.getByName("8.8.8.8"));
                listDns4.add(InetAddress.getByName("8.8.4.4"));
                if (ip6) {
                    listDns6.add(InetAddress.getByName("2001:4860:4860::8888"));
                    listDns6.add(InetAddress.getByName("2001:4860:4860::8844"));
                }

            } catch (Throwable ex) {
                Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
            }

            for (InetAddress dns : listLocal) {
                listDns.remove(dns);
                if (dns instanceof Inet4Address) {
                    if (listDns4.size() > 0) {
                        listDns.add(listDns4.get(0));
                        listDns4.remove(0);
                    }
                } else {
                    if (listDns6.size() > 0) {
                        listDns.add(listDns6.get(0));
                        listDns6.remove(0);
                    }
                }
            }
        }

        return listDns;
    }

    private ParcelFileDescriptor startVPN(Builder builder) throws SecurityException {
        try {
            return builder.establish();
        } catch (SecurityException ex) {
            throw ex;
        } catch (Throwable ex) {
            Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
            return null;
        }
    }

    private Builder getBuilder(List<Rule> listAllowed, List<Rule> listRule) {
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);
        boolean ip6 = prefs.getBoolean("ip6", true);
        boolean filter = prefs.getBoolean("filter", false);
        boolean system = prefs.getBoolean("manage_system", false);
        // Build VPN service
        Builder builder = new Builder();
        builder.setSession(getString(R.string.app_name));
        // VPN address
        String vpn4 = prefs.getString("vpn4", "10.1.10.1");
        Log.i(TAG, "vpn4=" + vpn4);
        builder.addAddress(vpn4, 32);
        if (ip6) {
            String vpn6 = prefs.getString("vpn6", "fd00:1:fd00:1:fd00:1:fd00:1");
            Log.i(TAG, "vpn6=" + vpn6);
            builder.addAddress(vpn6, 128);
        }
        // DNS address
        if (filter) for (InetAddress dns : getDns(ServiceSinkhole.this)) {
            if (ip6 || dns instanceof Inet4Address) {
                Log.i(TAG, "dns=" + dns);
                builder.addDnsServer(dns);
            }
        }
        Log.i(TAG, "IPv6=" + ip6);
        if (ip6) builder.addRoute("2000::", 3); // unicast
        // MTU
        int mtu = jni_get_mtu();
        Log.i(TAG, "MTU=" + mtu);
        builder.setMtu(mtu);
        // Add list of allowed applications
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP)
            if (last_connected && !filter) for (Rule rule : listAllowed)
                try {
                    builder.addDisallowedApplication(rule.packageName);
                } catch (PackageManager.NameNotFoundException ex) {
                    Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
                }
            else if (filter) {
                try {
                    builder.addDisallowedApplication(getPackageName());
                } catch (PackageManager.NameNotFoundException ex) {
                    Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
                }
                for (Rule rule : listRule)
                    if (!rule.apply || (!system && rule.system)) try {
                        Log.i(TAG, "Not routing " + rule.packageName);
                        builder.addDisallowedApplication(rule.packageName);
                    } catch (PackageManager.NameNotFoundException ex) {
                        Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
                    }
            }

        // Build configure intent
        Intent configure = new Intent(this, ActivityMain.class);
        PendingIntent pi = PendingIntent.getActivity(this, 0, configure, PendingIntent.FLAG_UPDATE_CURRENT);
        builder.setConfigureIntent(pi);

        return builder;
    }

    private void startNative(final ParcelFileDescriptor vpn, List<Rule> listAllowed, List<Rule> listRule) {
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(ServiceSinkhole.this);
        boolean log = prefs.getBoolean("log", false);
        boolean log_app = prefs.getBoolean("log_app", false);
        boolean filter = prefs.getBoolean("filter", false);

        Log.i(TAG, "Start native log=" + log + "/" + log_app + " filter=" + filter);
        prepareUidAllowed(listAllowed, listRule);

        int prio = Integer.parseInt(prefs.getString("loglevel", Integer.toString(Log.WARN)));
        final int rcode = Integer.parseInt(prefs.getString("rcode", "3"));
        if (tunnelThread == null) {
            Log.i(TAG, "Starting tunnel thread");
            jni_start(jni_context, prio);
            tunnelThread = new Thread(() -> {
                Log.i(TAG, "Running tunnel");
                jni_run(jni_context, vpn.getFd(), mapForward.containsKey(53), rcode);
                Log.i(TAG, "Tunnel exited");
                tunnelThread = null;
            });
            tunnelThread.setPriority(Thread.MAX_PRIORITY);
            tunnelThread.start();
            Log.i(TAG, "Started tunnel thread");
        }
    }

    private void stopNative(ParcelFileDescriptor vpn, boolean clear) {
        Log.i(TAG, "Stop native clear=" + clear);

        if (tunnelThread != null) {
            Log.i(TAG, "Stopping tunnel thread");

            jni_stop(jni_context);

            Thread thread = tunnelThread;
            while (thread != null) try {
                thread.join();
                break;
            } catch (InterruptedException ignored) {
            }
            tunnelThread = null;

            if (clear) jni_clear(jni_context);

            Log.i(TAG, "Stopped tunnel thread");
        }
    }

    private void unprepare() {
        lock.writeLock().lock();
        mapUidAllowed.clear();
        mapUidKnown.clear();
        mapHostsBlocked.clear();
        mapForward.clear();
        mapNotify.clear();
        lock.writeLock().unlock();
    }

    private void prepareUidAllowed(List<Rule> listAllowed, List<Rule> listRule) {
        lock.writeLock().lock();
        mapUidAllowed.clear();
        for (Rule rule : listAllowed)
            mapUidAllowed.put(rule.uid, true);
        mapUidKnown.clear();
        for (Rule rule : listRule)
            mapUidKnown.put(rule.uid, rule.uid);
        lock.writeLock().unlock();
    }

    private boolean isLockedDown(boolean metered) {
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(ServiceSinkhole.this);
        boolean lockdown = prefs.getBoolean("lockdown", false);
        boolean lockdown_wifi = prefs.getBoolean("lockdown_wifi", true);
        boolean lockdown_other = prefs.getBoolean("lockdown_other", true);
        if (metered ? !lockdown_other : !lockdown_wifi) lockdown = false;

        return lockdown;
    }

    private List<Rule> getAllowedRules(List<Rule> listRule) {
        List<Rule> listAllowed = new ArrayList<>();
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);
        // Check state
        boolean wifi = Util.isWifiActive(this);
        boolean metered = Util.isMeteredNetwork(this);
        boolean useMetered = prefs.getBoolean("use_metered", false);
        Set<String> ssidHomes = prefs.getStringSet("wifi_homes", new HashSet<String>());
        String ssidNetwork = Util.getWifiSSID(this);
        String generation = Util.getNetworkGeneration(this);
        boolean unmetered_2g = prefs.getBoolean("unmetered_2g", false);
        boolean unmetered_3g = prefs.getBoolean("unmetered_3g", false);
        boolean unmetered_4g = prefs.getBoolean("unmetered_4g", false);
        boolean roaming = Util.isRoaming(ServiceSinkhole.this);
        boolean national = prefs.getBoolean("national_roaming", false);
        boolean eu = prefs.getBoolean("eu_roaming", false);
        boolean tethering = prefs.getBoolean("tethering", false);
        boolean filter = prefs.getBoolean("filter", false);
        // Update connected state
        last_connected = Util.isConnected(ServiceSinkhole.this);
        boolean org_metered = metered;
        boolean org_roaming = roaming;
        // Update metered state
        if (wifi && !useMetered) metered = false;
        if (wifi && ssidHomes.size() > 0 && !(ssidHomes.contains(ssidNetwork) || ssidHomes.contains('"' + ssidNetwork + '"'))) {
            metered = true;
            Log.i(TAG, "!@home");
        }
        if (unmetered_2g && "2G".equals(generation)) metered = false;
        if (unmetered_3g && "3G".equals(generation)) metered = false;
        if (unmetered_4g && "4G".equals(generation)) metered = false;
        last_metered = metered;
        boolean lockdown = isLockedDown(last_metered);
        // Update roaming state
        if (roaming && eu) roaming = !Util.isEU(this);
        if (roaming && national) roaming = !Util.isNational(this);
        Log.i(TAG, "Get allowed" + " connected=" + last_connected + " wifi=" + wifi + " home=" + TextUtils.join(",", ssidHomes) + " network=" + ssidNetwork + " metered=" + metered + "/" + org_metered + " generation=" + generation + " roaming=" + roaming + "/" + org_roaming + " interactive=" + last_interactive + " tethering=" + tethering + " filter=" + filter + " lockdown=" + lockdown);
        if (last_connected) for (Rule rule : listRule) {
            boolean blocked = (metered ? rule.other_blocked : rule.wifi_blocked);
            boolean screen = (metered ? rule.screen_other : rule.screen_wifi);
            if ((!blocked || (screen && last_interactive)) && (!metered || !(rule.roaming && roaming)) && (!lockdown || rule.lockdown))
                listAllowed.add(rule);
        }

        Log.i(TAG, "Allowed " + listAllowed.size() + " of " + listRule.size());
        return listAllowed;
    }

    private void stopVPN(ParcelFileDescriptor pfd) {
        Log.i(TAG, "Stopping");
        try {
            pfd.close();
        } catch (IOException ex) {
            Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
        }
    }

    // Called from native code
    private void nativeExit(String reason) {
        Log.w(TAG, "Native exit reason=" + reason);
    }

    // Called from native code
    private void nativeError(int error, String message) {
        Log.w(TAG, "Native error " + error + ": " + message);
        showErrorNotification(message);
    }

    // Called from native code
    private void logPacket(Packet packet) {
        Log.d(TAG, "logPacket: " + packet);
    }

    // Called from native code
    private void dnsResolved(ResourceRecord rr) {

    }

    // Called from native code
    private boolean isDomainBlocked(String name) {
        Log.d(TAG, "isDomainBlocked: " + name);
        return false;
    }

    // Called from native code
    private Allowed isAddressAllowed(Packet packet) {
        Log.d(TAG, "isAddressAllowed: " + packet);
        return new Allowed();
    }

    // Called from native code
    private void accountUsage(Usage usage) {

    }

    @Override
    public void onCreate() {
        Log.i(TAG, "Create version=" + Util.getSelfVersionName(this) + "/" + Util.getSelfVersionCode(this));
        // Native init
        jni_context = jni_init(Build.VERSION.SDK_INT);
        Util.setTheme(this);
        super.onCreate();
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        start();
        return START_STICKY;
    }

    @Override
    public void onDestroy() {
        Log.i(TAG, "Destroy");
        try {
            if (vpn != null) {
                stopNative(vpn, true);
                stopVPN(vpn);
                vpn = null;
                unprepare();
            }
        } catch (Throwable ex) {
            Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
        }
        jni_done(jni_context);
        super.onDestroy();
    }

    private Notification getEnforcingNotification(int allowed, int blocked, int hosts) {
        Intent main = new Intent(this, ActivityMain.class);
        PendingIntent pi = PendingIntent.getActivity(this, 0, main, PendingIntent.FLAG_UPDATE_CURRENT);

        TypedValue tv = new TypedValue();
        getTheme().resolveAttribute(androidx.appcompat.R.attr.colorPrimary, tv, true);
        NotificationCompat.Builder builder = new NotificationCompat.Builder(this, "foreground");
        builder.setSmallIcon(isLockedDown(last_metered) ? R.drawable.ic_lock_outline_white_24dp : R.drawable.ic_security_white_24dp).setContentIntent(pi).setColor(tv.data).setOngoing(true).setAutoCancel(false);

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N)
            builder.setContentTitle(getString(R.string.msg_started));
        else
            builder.setContentTitle(getString(R.string.app_name)).setContentText(getString(R.string.msg_started));

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP)
            builder.setCategory(NotificationCompat.CATEGORY_STATUS).setVisibility(NotificationCompat.VISIBILITY_SECRET).setPriority(NotificationCompat.PRIORITY_MIN);

        if (allowed >= 0) last_allowed = allowed;
        else allowed = last_allowed;
        if (blocked >= 0) last_blocked = blocked;
        else blocked = last_blocked;
        if (hosts >= 0) last_hosts = hosts;
        else hosts = last_hosts;

        if (allowed >= 0 || blocked >= 0 || hosts >= 0) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                if (Util.isPlayStoreInstall(this))
                    builder.setContentText(getString(R.string.msg_packages, allowed, blocked));
                else builder.setContentText(getString(R.string.msg_hosts, allowed, blocked, hosts));
                return builder.build();
            } else {
                NotificationCompat.BigTextStyle notification = new NotificationCompat.BigTextStyle(builder);
                notification.bigText(getString(R.string.msg_started));
                if (Util.isPlayStoreInstall(this))
                    notification.setSummaryText(getString(R.string.msg_packages, allowed, blocked));
                else
                    notification.setSummaryText(getString(R.string.msg_hosts, allowed, blocked, hosts));
                return notification.build();
            }
        } else return builder.build();
    }

    private void updateEnforcingNotification(int allowed, int total) {
        // Update notification
        Notification notification = getEnforcingNotification(allowed, total - allowed, mapHostsBlocked.size());
        NotificationManager nm = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
        nm.notify(NOTIFY_ENFORCING, notification);
    }

    private void showErrorNotification(String message) {
        Intent main = new Intent(this, ActivityMain.class);
        PendingIntent pi = PendingIntent.getActivity(this, 0, main, PendingIntent.FLAG_UPDATE_CURRENT);

        TypedValue tv = new TypedValue();
        getTheme().resolveAttribute(R.attr.colorOff, tv, true);
        NotificationCompat.Builder builder = new NotificationCompat.Builder(this, "notify");
        builder.setSmallIcon(R.drawable.ic_error_white_24dp).setContentTitle(getString(R.string.app_name)).setContentText(getString(R.string.msg_error, message)).setContentIntent(pi).setColor(tv.data).setOngoing(false).setAutoCancel(true);

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP)
            builder.setCategory(NotificationCompat.CATEGORY_STATUS).setVisibility(NotificationCompat.VISIBILITY_SECRET);

        NotificationCompat.BigTextStyle notification = new NotificationCompat.BigTextStyle(builder);
        notification.bigText(getString(R.string.msg_error, message));
        notification.setSummaryText(message);

        NotificationManagerCompat.from(this).notify(NOTIFY_ERROR, notification.build());
    }

    public static void run(String reason, Context context) {
        Intent intent = new Intent(context, ServiceSinkhole.class);
        intent.putExtra(EXTRA_REASON, reason);
        ContextCompat.startForegroundService(context, intent);
    }

    public static void start(String reason, Context context) {
        Intent intent = new Intent(context, ServiceSinkhole.class);
        intent.putExtra(EXTRA_REASON, reason);
        ContextCompat.startForegroundService(context, intent);
    }

    public static void reload(String reason, Context context, boolean interactive) {
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(context);
        if (prefs.getBoolean("enabled", false)) {
            Intent intent = new Intent(context, ServiceSinkhole.class);
            intent.putExtra(EXTRA_REASON, reason);
            intent.putExtra(EXTRA_INTERACTIVE, interactive);
            ContextCompat.startForegroundService(context, intent);
        }
    }

    public static void stop(String reason, Context context, boolean vpnonly) {
        Intent intent = new Intent(context, ServiceSinkhole.class);
        intent.putExtra(EXTRA_REASON, reason);
        intent.putExtra(EXTRA_TEMPORARY, vpnonly);
        ContextCompat.startForegroundService(context, intent);
    }

    public static void reloadStats(String reason, Context context) {
        Intent intent = new Intent(context, ServiceSinkhole.class);
        intent.putExtra(EXTRA_REASON, reason);
        ContextCompat.startForegroundService(context, intent);
    }

    private class Builder extends VpnService.Builder {
        private NetworkInfo networkInfo;
        private int mtu;
        private List<String> listAddress = new ArrayList<>();
        private List<String> listRoute = new ArrayList<>();
        private List<InetAddress> listDns = new ArrayList<>();
        private List<String> listDisallowed = new ArrayList<>();

        private Builder() {
            super();
            ConnectivityManager cm = (ConnectivityManager) getSystemService(Context.CONNECTIVITY_SERVICE);
            networkInfo = cm.getActiveNetworkInfo();
        }

        @Override
        public VpnService.Builder setMtu(int mtu) {
            this.mtu = mtu;
            super.setMtu(mtu);
            return this;
        }

        @Override
        public Builder addAddress(String address, int prefixLength) {
            listAddress.add(address + "/" + prefixLength);
            super.addAddress(address, prefixLength);
            return this;
        }

        @Override
        public Builder addRoute(String address, int prefixLength) {
            listRoute.add(address + "/" + prefixLength);
            super.addRoute(address, prefixLength);
            return this;
        }

        @Override
        public Builder addDnsServer(InetAddress address) {
            listDns.add(address);
            super.addDnsServer(address);
            return this;
        }

        @Override
        public Builder addDisallowedApplication(String packageName) throws PackageManager.NameNotFoundException {
            listDisallowed.add(packageName);
            super.addDisallowedApplication(packageName);
            return this;
        }

        @Override
        public boolean equals(Object obj) {
            Builder other = (Builder) obj;

            if (other == null) return false;

            if (this.networkInfo == null || other.networkInfo == null || this.networkInfo.getType() != other.networkInfo.getType())
                return false;

            if (this.mtu != other.mtu) return false;

            if (this.listAddress.size() != other.listAddress.size()) return false;

            if (this.listRoute.size() != other.listRoute.size()) return false;

            if (this.listDns.size() != other.listDns.size()) return false;

            if (this.listDisallowed.size() != other.listDisallowed.size()) return false;

            for (String address : this.listAddress)
                if (!other.listAddress.contains(address)) return false;

            for (String route : this.listRoute)
                if (!other.listRoute.contains(route)) return false;

            for (InetAddress dns : this.listDns)
                if (!other.listDns.contains(dns)) return false;

            for (String pkg : this.listDisallowed)
                if (!other.listDisallowed.contains(pkg)) return false;

            return true;
        }
    }
}
