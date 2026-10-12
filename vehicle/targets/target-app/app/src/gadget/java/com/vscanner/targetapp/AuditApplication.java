package com.vscanner.targetapp;
// 仅用于授权测试，自有源码构建；加载发生在 Activity 与 ContentProvider 之前。
public final class AuditApplication extends android.app.Application {
    @Override protected void attachBaseContext(android.content.Context context) {
        super.attachBaseContext(context);
        System.loadLibrary("gadget");
    }
}
