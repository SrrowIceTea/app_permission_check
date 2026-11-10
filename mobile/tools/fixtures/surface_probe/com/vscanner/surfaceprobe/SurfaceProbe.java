package com.vscanner.surfaceprobe;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.ContentResolver;
import android.content.Context;
import android.media.MediaRecorder;
import android.net.Uri;
import android.os.Build;

/**
 * 仅用于授权测试（自有夹具）：L2 `observed_surface` 的正对照。
 *
 * 故意放三种「闭集看不见」的形态 + 一种「闭集看得见」的对照：
 *   1. {@link ClipboardManager#getPrimaryClip()} —— 闭集**已登记**（exact），应算「看得见」；
 *   2. {@link ContentResolver#openInputStream} —— 类登记了、这个方法没有（method_gap）；
 *   3. {@link MediaRecorder} —— 整类没登记（class_gap）；
 *   4. {@link Build#MODEL} —— 字段读取，闭集是方法表，本就看不见（单列 field_reads）。
 *
 * 若 L2 只复述危险 API 闭集，第 2/3/4 项就应当一个都报不出来；报出来了才证明它真的在测「闭集之外」。
 */
public final class SurfaceProbe {

    private SurfaceProbe() {
    }

    /** 闭集已登记：期望 registered=true、form=exact。 */
    public static String covered(Context ctx) {
        ClipboardManager cm = (ClipboardManager) ctx.getSystemService(Context.CLIPBOARD_SERVICE);
        ClipData clip = cm.getPrimaryClip();
        return clip == null ? null : String.valueOf(clip.getItemAt(0).getText());
    }

    /** 类登记、方法没登记：期望 registered=false、form=method_gap。 */
    public static void methodGap(ContentResolver cr, Uri uri) throws Exception {
        cr.openInputStream(uri).close();
    }

    /** 整类没登记：期望 registered=false、form=class_gap。 */
    public static void classGap() {
        MediaRecorder recorder = new MediaRecorder();
        recorder.release();
    }

    /** 字段通道：期望出现在 field_reads，且不进两个分母。 */
    public static String fieldRead() {
        return Build.MODEL;
    }
}
