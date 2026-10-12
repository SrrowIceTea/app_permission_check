// 仅用于授权测试。主机注入显式白名单；不允许空白名单或默认全进程。
export function packages() {
  const configured = "__VSCAN_SESSION_PACKAGES__";
  let value;
  try { value = JSON.parse(configured); } catch (_) { value = null; }
  if (!Array.isArray(value) || value.length === 0) return ['com.vscanner.targetapp', 'com.vscanner.targetapp2'];
  return value.filter(p => typeof p === 'string' && /^[A-Za-z][\w]*(\.[\w]+)+$/.test(p));
}
