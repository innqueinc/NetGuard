

package eu.faircode.netguard;


import android.app.Activity;
import android.content.Intent;
import android.net.VpnService;
import android.os.Bundle;
import android.widget.Toast;

/* this class is responsible for launching vpn service */
public class LaunchVPN extends Activity {

    private static final int START_VPN_PROFILE = 70;

    @Override
    public void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        launchVPN();
    }

    private void launchVPN() {
        Intent intent = VpnService.prepare(this);
        if (intent != null) {
            startActivityForResult(intent, START_VPN_PROFILE);
        } else {
            onActivityResult(START_VPN_PROFILE, Activity.RESULT_OK, null);
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == START_VPN_PROFILE) {
            switch (resultCode) {
                case Activity.RESULT_OK:
                    ServiceSinkhole.start(this);
                    break;
                case Activity.RESULT_CANCELED:
                    Toast.makeText(this, "VPN connection cancelled\\nDid you configure another VPN to be an always-on VPN?", Toast.LENGTH_LONG).show();
                    break;
            }
        }
        finish();
    }
}
