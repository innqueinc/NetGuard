package eu.faircode.netguard;

import android.content.Intent;
import android.os.Bundle;
import android.view.View;

import androidx.appcompat.app.AppCompatActivity;


public class LocalVPN extends AppCompatActivity {
    private static final int VPN_REQUEST_CODE = 0x0F;


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

    }

    public void connect(View v) {
        Intent intent = new Intent(this, LaunchVPN.class);
        startActivity(intent);
    }

}
