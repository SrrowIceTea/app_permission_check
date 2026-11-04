package com.vscanner.aaidprobe;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;

import com.google.android.gms.ads.identifier.AdvertisingIdClient;

import org.json.JSONObject;

import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;

/** 仅用于授权测试。 Calls the SDK on a worker and writes a redacted action receipt. */
public final class ProbeReceiver extends BroadcastReceiver {
    private static final String AD_ID = "com.google.android.gms.permission.AD_ID";
    private static final String ZERO_ID = "00000000-0000-0000-0000-000000000000";

    @Override
    public void onReceive(Context context, Intent intent) {
        String token = intent.getStringExtra("token");
        if (token == null || !token.matches("[0-9a-f]{32}")) return;
        PendingResult pending = goAsync();
        new Thread(() -> {
            try {
                JSONObject receipt = new JSONObject();
                receipt.put("token", token);
                receipt.put("target_sdk", context.getApplicationInfo().targetSdkVersion);
                receipt.put("permission_granted",
                        context.checkSelfPermission(AD_ID) == PackageManager.PERMISSION_GRANTED);
                try {
                    AdvertisingIdClient.Info info = AdvertisingIdClient.getAdvertisingIdInfo(context);
                    String id = info == null ? null : info.getId();
                    receipt.put("limit_ad_tracking", info != null && info.isLimitAdTrackingEnabled());
                    receipt.put("return_shape", id == null || id.isEmpty() ? "empty"
                            : ZERO_ID.equals(id) ? "zero" : "nonzero");
                } catch (Exception error) {
                    receipt.put("exception_class", error.getClass().getName());
                }
                try (FileOutputStream out = context.openFileOutput("aaid-" + token + ".json",
                        Context.MODE_PRIVATE)) {
                    out.write(receipt.toString().getBytes(StandardCharsets.UTF_8));
                }
            } catch (Exception error) {
                android.util.Log.e("VScanAaidProbe", "Receipt failed: " + error.getClass().getName());
            } finally {
                pending.finish();
            }
        }, "vscan-aaid-probe").start();
    }
}
