package eu.faircode.netguard;

import android.content.Intent;
import android.os.Bundle;
import android.view.View;

import androidx.appcompat.app.AppCompatActivity;

public class MainActivity extends AppCompatActivity {
    static {
        try {
            System.loadLibrary("netguard");
        } catch (UnsatisfiedLinkError ignored) {
            System.exit(1);
        }
    }

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