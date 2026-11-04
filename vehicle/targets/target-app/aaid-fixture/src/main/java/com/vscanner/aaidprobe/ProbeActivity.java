package com.vscanner.aaidprobe;

import android.app.Activity;
import android.os.Bundle;
import android.widget.TextView;

/** 仅用于授权测试。 Keeps the ordinary fixture process available for attach. */
public final class ProbeActivity extends Activity {
    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        TextView view = new TextView(this);
        view.setText("V-Scanner AAID acceptance fixture");
        setContentView(view);
    }
}
