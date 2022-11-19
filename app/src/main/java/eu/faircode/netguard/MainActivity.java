package eu.faircode.netguard;

import android.content.Intent;
import android.net.VpnService;
import android.os.Bundle;
import android.view.View;

import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;

public class MainActivity extends AppCompatActivity {

    private static final int REQUEST_VPN = 1;
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
    }
    public void connect(View view) {
        final Intent prepare = VpnService.prepare(this);
        if (prepare == null) {
            onActivityResult(REQUEST_VPN, RESULT_OK, null);
        }else{
            startActivityForResult(prepare, REQUEST_VPN);
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, @Nullable Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        ServiceSinkhole.start("prepared", this);
    }
}