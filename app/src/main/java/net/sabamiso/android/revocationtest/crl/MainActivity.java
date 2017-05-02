package net.sabamiso.android.revocationtest.crl;

import android.graphics.Color;
import android.os.Handler;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.Spinner;
import android.widget.TextView;
import android.widget.Toast;

import static net.sabamiso.android.revocationtest.crl.RevocationResult.*;

enum RevocationResult {NONE, REVOKED, NOT_REVOKED};

public class MainActivity extends AppCompatActivity implements Runnable {

    Button buttonCheck;
    Spinner spinnerTargetUrl;
    TextView testViewResult;

    String target_url_str;
    long start_t ;
    RevocationResult revocation_result = NONE;

    Handler handler = new Handler();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        String [] urls = new String[] {
                "https://revoked.badssl.com/",
                "https://revoked.grc.com",
                "https://google.com/",
                "https://www.symantec.com/"
        };

        spinnerTargetUrl = (Spinner)findViewById(R.id.spinnerTargetUrl);
        ArrayAdapter<String> adapter = new ArrayAdapter<String>(this,
                android.R.layout.simple_spinner_item, urls);
        spinnerTargetUrl.setAdapter(adapter);

        buttonCheck = (Button)findViewById(R.id.buttonCheck);
        buttonCheck.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                onButtonPressed();
            }
        });

        testViewResult = (TextView)findViewById(R.id.textViewResult);
        testViewResult.setBackgroundColor(Color.parseColor("#00000000"));
        testViewResult.setText("");
    }

    void onButtonPressed() {
        buttonCheck.setEnabled(false);
        revocation_result = NONE;
        updateUI();

        target_url_str = spinnerTargetUrl.getSelectedItem().toString();
        Thread t = new Thread(this);
        t.start();
    }

    public void run() {
        try {
            start_t = System.currentTimeMillis();
            boolean rv = RevocationTestUsingCRL.isRevoked(target_url_str, true);
            if (rv) {
                revocation_result = REVOKED;
            }
            else {
                revocation_result = NOT_REVOKED;
            }
        } catch (RevocationTestException e) {
            e.printStackTrace();
        }

        final long t = System.currentTimeMillis() - start_t;

        handler.post(new Runnable() {
            @Override
            public void run() {
                updateUI();
                buttonCheck.setEnabled(true);
                Toast.makeText(MainActivity.this, "process time=" + t + "(ms)", Toast.LENGTH_LONG).show();
            }
        });
    }

    void updateUI() {
        buttonCheck.setEnabled(true);
        switch (revocation_result) {
            case NONE:
                testViewResult.setBackgroundColor(Color.argb(0, 0, 0, 0));
                testViewResult.setText("");
                break;
            case REVOKED:
                testViewResult.setBackgroundColor(Color.argb(255, 255, 0, 0));
                testViewResult.setTextColor(Color.WHITE);
                testViewResult.setText("REVOKED");
                break;
            case NOT_REVOKED:
                testViewResult.setBackgroundColor(Color.argb(255, 0, 255, 0));
                testViewResult.setTextColor(Color.BLACK);
                testViewResult.setText("NOT_REVOKED");
                break;
        }

    }
}
