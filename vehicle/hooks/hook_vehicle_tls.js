// ============================================================================
// 仅用于授权测试（自有设备与自有 APK）。
// 车载采集的明文可见性聚合层：BoringSSL 与 JCE 两条路径。
//
// 为什么需要这一层：hook_native_ssl.js 与 hook_cipher.js 都是
// `export function main()` 的**不自执行**模块（见各自文件末尾说明：ESM import 会被
// 提升到 `globalThis.Java = Java` 之前，side-effect import 会直接
// `ReferenceError: 'Java' is not defined`）。此前只有单独 bundle 会跑它们，
// 车载的 hook_vehicle_all 从未调用，所以加密流量在车载侧**只有属性名匹配、
// 没有值级证据**。这里补上装配点。
//
// 覆盖分工：
//   native_ssl —— TLS 记录层，SSL_write/SSL_read 的 buf 即明文（BoringSSL）。
//   cipher     —— 应用层 JCE，Cipher.update/doFinal 的入参/返回值即明文。
// 两者互补：native 覆盖标准 TLS 栈，cipher 覆盖自绘加密后再外发。
//
// 只观察，不阻断、不改值。每个模块独立 try/catch：本进程没有导出符号或没有 JCE 时，
// 另一个仍要装上，并且绝不影响 VHAL 主链。
// ============================================================================
'use strict';

import { main as armNativeTls } from './hook_native_ssl.js';
import { main as armCipher } from './hook_cipher.js';
import { makeLogger } from './vscan_runtime.js';

var vlog = makeLogger('vehicle_tls', '/data/local/tmp/vscan.log');

export function armVehicleTls() {
  var armed = [];
  var failures = [];
  try {
    armNativeTls();
    armed.push('native_ssl');
  } catch (e) {
    failures.push({ module: 'native_ssl', msg: String(e && e.stack ? e.stack : e) });
  }
  try {
    armCipher();
    armed.push('cipher');
  } catch (e) {
    failures.push({ module: 'cipher', msg: String(e && e.stack ? e.stack : e) });
  }
  // 汇总一行，便于在 reads.jsonl 里一眼看出本轮明文通道是否就位。
  vlog('TLS_MODULES', {
    armed: armed,
    failed: failures.map(function (row) { return row.module; }),
    note: '缺少模块不等于没有外发；只表示该路径的明文在本轮不可见。'
  });
  for (var i = 0; i < failures.length; i++) {
    vlog('ERROR', { where: 'arm_' + failures[i].module, msg: failures[i].msg });
  }
  return armed;
}
