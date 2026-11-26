// 仅用于授权测试（自有设备与自有 APK）/ For authorized testing on owned devices and APKs only.
// V-Scanner F1 — classload_attribution.js：运行时类名的宿主 / 第三方 / 未知归因
//
// 这是**归因**，不是判定。输出只有三种 origin：
//   host                 类名落在宿主包名下（`host + '.'`，不能用子串，见下）
//   third_party:<prefix> 命中下面种子表里明确知道的 SDK 包前缀
//   unknown              其余一切——**绝不因为"看起来像 SDK"就猜一个前缀**
// 未知一律 unknown 这条与项目"绝不编造"同源：把 androidx 猜成某 SDK，报告就会
// 出现一个不存在的收集方，而且没有任何地方会报错。
//
// class_kind 是给 unknown 拆噪声用的**事实分类**（platform / support_library / other），
// 不改变 origin：androidx 不是数据收集 SDK，但它也不是宿主代码。
//
// 种子表是**有界**的（前 30 个主流 SDK 包前缀，PoPETS'25 类名前缀归因思路）。
// 未收录的库不会消失，只是落在 unknown；报告必须同时给出 uncovered_by_design。
//
// 归一化两件事，都是实测会静默掉进 unknown 的：
//   1. 数组描述符 `[Lcom.google.firebase.Foo;`——`findClass` 会收到这种名字；
//   2. 内部类 `com.google.firebase.Foo$Bar`——前缀匹配必须按包边界，不能按整串。

export const HOST = 'host';
export const THIRD_PARTY = 'third_party';
export const UNKNOWN = 'unknown';

// 前 30 个主流 SDK 包前缀。只收**包边界明确**的：`com.adjust.sdk` 而不是 `com.adjust`，
// 避免把同公司的非 SDK 模块一起算进来。匹配用最长前缀，见 matchSdk。
export const SDK_PREFIXES = [
  {prefix: 'com.google.android.gms', sdk: 'Google Play services'},
  {prefix: 'com.google.firebase', sdk: 'Firebase'},
  {prefix: 'com.google.android.play', sdk: 'Play Core'},
  {prefix: 'com.facebook', sdk: 'Facebook SDK'},
  {prefix: 'com.appsflyer', sdk: 'AppsFlyer'},
  {prefix: 'com.adjust.sdk', sdk: 'Adjust'},
  {prefix: 'com.onesignal', sdk: 'OneSignal'},
  {prefix: 'com.mixpanel', sdk: 'Mixpanel'},
  {prefix: 'com.amplitude', sdk: 'Amplitude'},
  {prefix: 'com.flurry', sdk: 'Flurry'},
  {prefix: 'com.umeng', sdk: 'Umeng'},
  {prefix: 'com.tencent.bugly', sdk: 'Bugly'},
  {prefix: 'com.tencent.stat', sdk: 'Tencent MTA'},
  {prefix: 'com.tencent.mm.opensdk', sdk: 'WeChat OpenSDK'},
  {prefix: 'com.alipay', sdk: 'Alipay SDK'},
  {prefix: 'com.bytedance', sdk: 'ByteDance SDK'},
  {prefix: 'com.pangle', sdk: 'Pangle'},
  {prefix: 'com.unity3d.ads', sdk: 'Unity Ads'},
  {prefix: 'com.applovin', sdk: 'AppLovin'},
  {prefix: 'com.mopub', sdk: 'MoPub'},
  {prefix: 'com.ironsource', sdk: 'ironSource'},
  {prefix: 'com.vungle', sdk: 'Vungle'},
  {prefix: 'com.chartboost', sdk: 'Chartboost'},
  {prefix: 'com.crashlytics', sdk: 'Crashlytics (legacy)'},
  {prefix: 'io.sentry', sdk: 'Sentry'},
  {prefix: 'io.branch', sdk: 'Branch'},
  {prefix: 'io.appmetrica', sdk: 'AppMetrica'},
  {prefix: 'com.huawei.hms', sdk: 'HMS Core'},
  {prefix: 'com.huawei.agconnect', sdk: 'AppGallery Connect'},
  {prefix: 'com.amazon.device.ads', sdk: 'Amazon Ads'}
];

// 只用于解释 unknown 的构成，不参与 origin 判定。
const PLATFORM_PREFIXES = ['java.', 'javax.', 'jdk.', 'sun.', 'libcore.', 'dalvik.', 'android.'];
const SUPPORT_PREFIXES = [
  'androidx.', 'android.support.', 'kotlin.', 'kotlinx.', 'org.jetbrains.',
  'com.google.android.material.', 'com.google.gson.', 'com.google.common.',
  'com.google.protobuf.', 'com.bumptech.glide.',
  'okhttp3.', 'okio.', 'retrofit2.', 'org.json.', 'org.xmlpull.', 'io.reactivex.',
  'org.greenrobot.', 'com.squareup.', 'org.bouncycastle.', 'io.grpc.', 'org.apache.'
];

// 栈里"不是调用方"的帧：反射/动态代理/Binder 与 ART 内部帧。归因要穿过它们，
// 否则每个 SDK 反射读取都会被记成 java.lang.reflect.Method（unknown）。
const TRANSPARENT_PREFIXES = [
  'java.lang.reflect.', 'java.lang.Class.', 'java.lang.Thread.',
  'dalvik.system.', 'android.os.Binder', 'com.android.internal.os.',
  'com.android.internal.util.', 'jdk.internal.'
];

const SDK_BY_SPECIFICITY = SDK_PREFIXES.slice()
  .sort((a, b) => b.prefix.length - a.prefix.length);

// `[Lcom.foo.Bar;` / `[[Lcom.foo.Bar;` / `Lcom.foo.Bar;` -> `com.foo.Bar`
export function normalizeClass(name) {
  var text = String(name == null ? '' : name).trim();
  while (text.charAt(0) === '[') text = text.slice(1);
  if (text.charAt(0) === 'L' && text.charAt(text.length - 1) === ';') text = text.slice(1, -1);
  return text;
}

// 包边界匹配：`com.foo` 匹配 `com.foo.Bar`，不匹配 `com.foobar.Baz`。
function under(name, prefix) {
  return name === prefix || name.indexOf(prefix + '.') === 0;
}

export function packageOf(className) {
  var name = normalizeClass(className);
  var cut = name.lastIndexOf('.');
  if (cut <= 0) return null;
  return name.slice(0, cut);
}

// 未知类只报"它自己的包根"这一**事实**（默认前三段），不冒充 SDK 前缀。
export function packageRoot(className, depth) {
  var pkg = packageOf(className);
  if (!pkg) return null;
  var parts = pkg.split('.');
  return parts.slice(0, depth || 3).join('.');
}

export function matchSdk(className) {
  var name = normalizeClass(className);
  for (var i = 0; i < SDK_BY_SPECIFICITY.length; i++) {
    if (under(name, SDK_BY_SPECIFICITY[i].prefix)) return SDK_BY_SPECIFICITY[i];
  }
  return null;
}

export function classKind(className, hostPackage) {
  var name = normalizeClass(className);
  if (!name) return 'other';
  if (hostPackage && under(name, hostPackage)) return 'host';
  if (matchSdk(name)) return 'sdk';
  for (var i = 0; i < PLATFORM_PREFIXES.length; i++) {
    if (name.indexOf(PLATFORM_PREFIXES[i]) === 0) return 'platform';
  }
  for (var j = 0; j < SUPPORT_PREFIXES.length; j++) {
    if (name.indexOf(SUPPORT_PREFIXES[j]) === 0) return 'support_library';
  }
  return 'other';
}

// 主入口。host 判定放在 SDK 之前：宿主自己的包永远算 host，
// 哪怕它恰好落在某个公司命名空间下（例如宿主就是 com.facebook 的自家应用）。
export function attribute(className, hostPackage) {
  var name = normalizeClass(className);
  if (!name) return {origin: UNKNOWN, class_kind: 'other', sdk_prefix: null,
                     sdk_name: null, package_root: null, normalized: ''};
  var kind = classKind(name, hostPackage);
  var sdk = matchSdk(name);
  return {
    origin: kind === 'host' ? HOST : (sdk ? THIRD_PARTY + ':' + sdk.prefix : UNKNOWN),
    class_kind: kind,
    sdk_prefix: sdk ? sdk.prefix : null,
    sdk_name: sdk ? sdk.sdk : null,
    package_root: packageRoot(name),
    normalized: name
  };
}

// `com.foo.Bar.baz(Bar.java:12)` -> `com.foo.Bar`；构造器 `<init>` 与 lambda 同样适用。
export function frameClass(frame) {
  var text = String(frame == null ? '' : frame);
  var cut = text.indexOf('(');
  var head = cut >= 0 ? text.slice(0, cut) : text;
  var dot = head.lastIndexOf('.');
  return dot > 0 ? head.slice(0, dot) : null;
}

export function frameMethod(frame) {
  var text = String(frame == null ? '' : frame);
  var cut = text.indexOf('(');
  var head = cut >= 0 ? text.slice(0, cut) : text;
  var dot = head.lastIndexOf('.');
  return dot > 0 ? head.slice(dot + 1) : null;
}

export function isTransparentFrame(frame) {
  var cls = frameClass(frame);
  if (!cls) return true;
  for (var i = 0; i < TRANSPARENT_PREFIXES.length; i++) {
    if (cls.indexOf(TRANSPARENT_PREFIXES[i]) === 0) return true;
  }
  // 动态代理：`com.foo.$Proxy0` / `$Proxy12`
  return /(^|\.)\$Proxy\d+$/.test(cls);
}

// 从栈顶往下找第一个"真实调用方"：跳过被挂钩的 API 自己与反射/Binder 帧。
// apiClass/apiMethod 可省略（此时只跳透明帧）。
export function callerClass(frames, apiClass, apiMethod) {
  if (!frames || typeof frames.length !== 'number') return null;
  for (var i = 0; i < frames.length; i++) {
    var cls = frameClass(frames[i]);
    if (!cls) continue;
    if (apiClass && cls === apiClass && (!apiMethod || frameMethod(frames[i]) === apiMethod)) continue;
    if (isTransparentFrame(frames[i])) continue;
    return cls;
  }
  return null;
}

export const SDK_TABLE_SIZE = SDK_PREFIXES.length;
