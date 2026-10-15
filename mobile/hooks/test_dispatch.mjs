// 仅用于授权测试（已获授权的样本与设备）。
// 钩子纯逻辑的离线回归 —— 不需要设备、不需要 Frida。
//
// 跑法：node test_dispatch.mjs
//
// 为什么值得单独测：这些判断错了不会报错，只会让**某类数据从来没被判出来**，
// 或者反过来把不相干的调用记成敏感读取。两种都是静默失败。
import assert from 'node:assert/strict';
import { matchBySpec, isDeniedClassName, describeException, looksLikePolicy, discriminator, unmappedKey,
         toJsArray, shortName, splitGrantResults, preview } from './dispatch.js';

let pass = 0, fail = 0;
function t(name, fn) {
  try { fn(); pass++; console.log(`  ok  ${name}`); }
  catch (e) { fail++; console.log(`FAIL  ${name}\n      ${e.message}`); }
}

console.log('dispatch.js');

// --- matchBySpec: direct ---
t('direct 规格用 fallback 数据类别', () => {
  assert.deepEqual(matchBySpec({ kind: 'direct' }, [], 'imei'), ['imei']);
});
t('direct 且无 fallback → 空（不猜）', () => {
  assert.deepEqual(matchBySpec({ kind: 'direct' }, [], null), []);
});
t('无 spec 时退回 fallback', () => {
  assert.deepEqual(matchBySpec(undefined, [], 'contacts'), ['contacts']);
});

// --- matchBySpec: string_key_arg (Settings.Secure) ---
const keySpec = { kind: 'string_key_arg', arg_index: 1, map: [{ value: 'android_id', data_type: 'android_id' }] };
t('Settings.Secure key=android_id → android_id', () => {
  assert.deepEqual(matchBySpec(keySpec, [{}, 'android_id'], null), ['android_id']);
});
t('Settings.Secure 未映射的 key → 空（必须留痕，不是静默读取）', () => {
  assert.deepEqual(matchBySpec(keySpec, [{}, 'bluetooth_address'], null), []);
});

// --- matchBySpec: provider_arg (LocationManager) ---
const provSpec = { kind: 'provider_arg', arg_index: 0,
                   map: { gps: 'precise_location', network: 'coarse_location' } };
t('provider=gps → 精确定位', () => {
  assert.deepEqual(matchBySpec(provSpec, ['gps'], null), ['precise_location']);
});
t('provider=network → 粗略定位', () => {
  assert.deepEqual(matchBySpec(provSpec, ['network'], null), ['coarse_location']);
});
t('未知 provider → 空', () => {
  assert.deepEqual(matchBySpec(provSpec, ['fused_custom'], null), []);
});

// --- matchBySpec: content_uri (ContentResolver.query) ---
const uriSpec = { kind: 'content_uri', arg_index: 0, match: 'prefix',
                  map: [{ prefix: 'content://com.android.contacts', data_type: 'contacts' },
                        { prefix: 'content://sms', data_type: 'sms' },
                        { prefix: 'content://media/external/images', data_type: 'media_images' }] };
t('contacts URI → contacts', () => {
  assert.deepEqual(matchBySpec(uriSpec, ['content://com.android.contacts/data/phones'], null),
                   ['contacts']);
});
t('sms URI → sms', () => {
  assert.deepEqual(matchBySpec(uriSpec, ['content://sms/inbox'], null), ['sms']);
});
t('media 子路径前缀匹配', () => {
  assert.deepEqual(matchBySpec(uriSpec, ['content://media/external/images/media'], null),
                   ['media_images']);
});
t('**前缀必须从头匹配**：伪装 URI 不算命中（防止 contains 误报）', () => {
  assert.deepEqual(matchBySpec(uriSpec, ['content://evil.example/x?u=content://sms'], null), []);
});
t('未映射 URI → 空', () => {
  assert.deepEqual(matchBySpec(uriSpec, ['content://com.vendor.custom/table'], null), []);
});
t('URI 为 null 不抛异常、返回空', () => {
  assert.deepEqual(matchBySpec(uriSpec, [null], null), []);
});

// --- isDeniedClassName ---
t('SecurityException 算权限拒绝', () => {
  assert.equal(isDeniedClassName('java.lang.SecurityException'), true);
});
t('权限类异常算拒绝', () => {
  assert.equal(isDeniedClassName('java.lang.SecurityException$Permission'), true);
});
t('普通异常不算拒绝（否则"脚本出错"会被报成"权限被拒"）', () => {
  assert.equal(isDeniedClassName('java.lang.NullPointerException'), false);
  assert.equal(isDeniedClassName(''), false);
  assert.equal(isDeniedClassName(null), false);
});

// --- Java errors wrapped by Frida 17: anchored diagnosis only ---
t('direct Java class wins and original wrapper/message remain available', () => {
  const msg = 'original message java.lang.NullPointerException: context';
  const result = describeException({ $className: 'java.lang.SecurityException', name: 'Error', message: msg });
  assert.equal(result.class_name, 'java.lang.SecurityException');
  assert.equal(result.wrapper_class, 'java.lang.SecurityException');
  assert.equal(result.class_source, 'java_class');
  assert.equal(result.message, msg);
  assert.equal(result.denied, true);
});
t('wrapped SecurityException is denied with Error wrapper preserved', () => {
  const msg = 'java.lang.SecurityException: caller has no READ_PHONE_NUMBERS';
  const result = describeException(new Error(msg));
  assert.equal(result.class_name, 'java.lang.SecurityException');
  assert.equal(result.wrapper_class, 'Error');
  assert.equal(result.class_source, 'wrapper_message_prefix');
  assert.equal(result.message, msg);
  assert.equal(result.denied, true);
});
t('all exact known denied prefixes work when class is missing', () => {
  for (const cls of ['java.lang.SecurityException', 'java.lang.PermissionDeniedException',
                     'android.permission.PermissionDeniedException']) {
    const result = describeException({ message: cls + ': explicitly denied' });
    assert.equal(result.class_name, cls);
    assert.equal(result.wrapper_class, null);
    assert.equal(result.denied, true);
  }
});
t('actual Java non-denial class cannot be replaced by denial-like message', () => {
  const result = describeException({ $className: 'java.lang.NullPointerException', name: 'Error',
                                     message: 'java.lang.SecurityException: mentioned context' });
  assert.equal(result.class_name, 'java.lang.NullPointerException');
  assert.equal(result.denied, false);
});
t('typed JS errors remain errors despite a denied-class prefix', () => {
  const result = describeException(new TypeError('java.lang.SecurityException: not a Java wrapper'));
  assert.equal(result.class_name, 'TypeError');
  assert.equal(result.denied, false);
});
t('ordinary errors and permission mentions never imply denial', () => {
  for (const msg of ['READ_PHONE_NUMBERS permission required',
                     'observed java.lang.SecurityException: while reporting another error',
                     'Caused by: java.lang.SecurityException: context',
                     ' java.lang.SecurityException: leading space',
                     'java.lang.SecurityExceptionSpoof: forged class',
                     'evil.java.lang.SecurityException: suffix is not the class',
                     'java.lang.SecurityException$Permission: unknown wrapped subclass',
                     'java.lang.NullPointerException: data unavailable']) {
    assert.equal(describeException(new Error(msg)).denied, false, msg);
  }
});
t('denied class matches exact or nested Java class boundaries only', () => {
  assert.equal(isDeniedClassName('java.lang.SecurityException$Permission'), true);
  assert.equal(isDeniedClassName('evil.java.lang.SecurityException'), false);
  assert.equal(isDeniedClassName('java.lang.SecurityExceptionSpoof'), false);
  assert.equal(isDeniedClassName('message java.lang.SecurityException: denied'), false);
});
t('wrapper helper preserves untruncated message for caller preview policy', () => {
  const msg = 'java.lang.SecurityException: ' + 'x'.repeat(300);
  assert.equal(describeException(new Error(msg)).message, msg);
});

// --- looksLikePolicy ---
t('英文隐私政策 URL 命中', () => {
  assert.equal(looksLikePolicy('https://x.example/privacy/policy.html'), true);
});
t('中文"隐私政策"命中', () => {
  assert.equal(looksLikePolicy('https://x.example/隐私政策'), true);
});
t('普通页面不命中（避免日志噪声）', () => {
  assert.equal(looksLikePolicy('https://x.example/home/index.html'), false);
});
t('大小写不敏感', () => {
  assert.equal(looksLikePolicy('https://X.example/PRIVACY'), true);
});

// --- discriminator / unmappedKey ---
t('判别值超长截断到 200', () => {
  const out = discriminator(uriSpec, ['content://x/' + 'a'.repeat(500)]);
  assert.equal(out.length, 201);   // 200 + '…'
});
t('判别值取的是 arg_index 指定的那个实参', () => {
  assert.equal(discriminator(keySpec, ['ContentResolver@1', 'android_id']), 'android_id');
});
t('unmappedKey 去掉 query（避免同种 URI 记很多条）', () => {
  const k1 = unmappedKey({ cls: 'X' }, uriSpec, ['content://a/b?p=1']);
  const k2 = unmappedKey({ cls: 'X' }, uriSpec, ['content://a/b?p=2']);
  assert.equal(k1, k2);
});

// --- toJsArray / shortName ---
t('toJsArray 处理 Java 数组形态', () => {
  const fake = { length: 2, 0: 'a', 1: 'b' };
  assert.deepEqual(toJsArray(fake), ['a', 'b']);
});
t('toJsArray 对 null 返回空数组', () => {
  assert.deepEqual(toJsArray(null), []);
});
t('shortName 取权限短名', () => {
  assert.equal(shortName('android.permission.READ_CONTACTS'), 'READ_CONTACTS');
});

// --- splitGrantResults：部分授权是"同意前收集"判定的关键 ---
t('部分授权：granted/denied 逐条分开', () => {
  const r = splitGrantResults(['android.permission.READ_CONTACTS',
                               'android.permission.ACCESS_FINE_LOCATION'], [0, -1]);
  assert.deepEqual(r.granted, ['READ_CONTACTS']);
  assert.deepEqual(r.denied, ['ACCESS_FINE_LOCATION']);
  assert.deepEqual(r.other, []);
});
t('全部同意', () => {
  const r = splitGrantResults(['p.A', 'p.B'], [0, 0]);
  assert.deepEqual(r.granted, ['A', 'B']);
  assert.deepEqual(r.denied, []);
});
t('非 0/-1 的结果单独归类，不当作同意也不当作拒绝', () => {
  const r = splitGrantResults(['p.A'], [1]);
  assert.deepEqual(r.granted, []);
  assert.deepEqual(r.denied, []);
  assert.deepEqual(r.other, [{ permission: 'A', result: 1 }]);
});

// --- preview ---
t('preview 短串原样返回', () => { assert.equal(preview('46000', 6), '46000'); });
t('preview 长串截断加省略号', () => { assert.equal(preview('460001234567890', 6), '460001…'); });

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
