// ============================================================================
// 仅用于授权测试（自有设备与自有 APK）/ For authorized testing on owned devices and APKs only.
// V-Scanner Phase 3 — stack_capture.js：Java 调用栈采集（多个钩子共用）
//
// 从当前线程的 Java 栈里挑出「应用自己的帧」——那是代码定位（违规行号）的唯一依据。
// 三条铁律（都是实测踩过的坑，见 hook_egress.js / phase5 D507/D508）：
//   1. 栈顶永远不是答案（栈顶是钩子自己 / 框架内部）。
//   2. 不能按位置取前 N 帧，要按归属筛——应用帧恰好在截断点之外。
//   3. 合成帧（R8/D8 lambda、Synthetic、行号 0）长得像真帧，行号级过滤由下游做。
// 为什么抽出来：hook_egress.js 里已有同一份逻辑，hook_cipher / hook_native_ssl 还要用；
// 三个入口各写一份必然再次漂移（见 vscan_runtime.js 顶部那场漂移事故）。
// ============================================================================

export function captureStack(PKG, maxContext, maxApp) {
  try {
    var frames = Java.use('java.lang.Thread').currentThread().getStackTrace();
    var context = [], app = [], skipped = 0;
    for (var i = 0; i < frames.length; i++) {
      var s = String(frames[i].toString());
      if (s.indexOf('VMStack') >= 0 || s.indexOf('Thread.getStackTrace') >= 0) continue;
      // `PKG + '.'` 而非 indexOf(PKG)：targetapp 是 targetapp2 的前缀，子串会把 B 算成 A。
      if (PKG && PKG !== 'unknown' && s.indexOf(PKG + '.') >= 0) {
        if (app.length < maxApp) app.push(s);
        else skipped++;
      } else if (context.length < maxContext) {
        context.push(s);
      }
    }
    var out = { stack: context, app_frames: app };
    // 应用帧多到装不下时报个数，别静默截断——静默截断正是当年那个 bug。
    if (skipped > 0) out.app_frames_skipped = skipped;
    return out;
  } catch (e) { return { stack: [], app_frames: [] }; }
}

// 把 captureStack 的两个字段摊平进 extra（同 hook_egress.js 的 withStack）。
export function withStack(extra, PKG, maxContext, maxApp) {
  var st = captureStack(PKG, maxContext, maxApp);
  extra.stack = st.stack;
  extra.app_frames = st.app_frames;
  if (st.app_frames_skipped) extra.app_frames_skipped = st.app_frames_skipped;
  return extra;
}
