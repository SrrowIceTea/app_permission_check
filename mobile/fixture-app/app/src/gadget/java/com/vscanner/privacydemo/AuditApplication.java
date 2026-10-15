package com.vscanner.privacydemo;

// Only the gadget build type includes this owned-fixture early loader.
// Authorized testing only. No root, system CA changes, or third-party APK rewriting.
public final class AuditApplication extends android.app.Application {
    @Override protected void attachBaseContext(android.content.Context context) {
        super.attachBaseContext(context);
        System.loadLibrary("gadget");
    }
}
