// 仅用于授权测试（已获授权的样本与设备）。主机注入显式白名单；不允许空白名单或默认全进程。
// `__VSCAN_SESSION_PACKAGES__` 是宿主机（core/frida_host/run.py 的 bundle_config）在注入前
// 逐模块替换的占位符——替换时会重算模块字节长度头，所以这里必须是**字面量**。
export function packages() {
  const configured = "__VSCAN_SESSION_PACKAGES__";
  let value;
  try { value = JSON.parse(configured); } catch (_) { value = null; }
  if (!Array.isArray(value) || value.length === 0) return ['com.vscanner.privacydemo'];
  return value.filter(p => typeof p === 'string' && /^[A-Za-z][\w]*(\.[\w]+)+$/.test(p));
}
