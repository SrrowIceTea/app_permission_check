// 仅用于授权测试。Observe only the owned fixture's explicit read marker.
'use strict';
import { makeLogger, decodeUtf8 } from './runtime.js';
import { packages } from './scope.js';
import { WATCH } from './targets.generated.js';

const PKG = 'com.vscanner.privacydemo';
const TAG = 'VScanWindowObserve';
const KIND = 'fixture_native_log';
const log = makeLogger('privacy', '/data/local/tmp/vscan-mobile.log');

export function main() {
  try {
    const whitelist = packages();
    const cmdline = new File('/proc/self/cmdline', 'r');
    let name;
    try { name = decodeUtf8(new Uint8Array(cmdline.readBytes(512))).split('\0', 1)[0]; }
    finally { cmdline.close(); }
    if (whitelist.length !== 1 || whitelist[0] !== PKG || name !== PKG) {
      throw new Error('owned benchmark process required');
    }

    const target = WATCH.find(entry => entry.cls === 'android.provider.Settings$Secure' &&
      entry.method === 'getString' && entry.spec.map.some(mapping => mapping.data_type === 'android_id'));
    if (!target) throw new Error('Android ID rule metadata missing');
    const logWrite = Process.getModuleByName('liblog.so').getExportByName('__android_log_buf_write');
    log('START', {pkg: PKG, whitelist, hook: KIND});
    Interceptor.attach(logWrite, {
      onEnter(args) {
        try {
          if (args[2].isNull() || args[2].readCString() !== TAG) return;
          const marker = JSON.parse(args[3].readCString());
          if (!/^[a-f0-9]{32}$/.test(marker.run) || !/^[ab]$/.test(marker.batch) ||
              !/^[a-f0-9]{64}$/.test(marker.value_sha256)) {
            throw new Error('invalid read marker');
          }
          const read = {
            api: target.cls + '.' + target.method + target.desc, api_role: 'query',
            data_types: ['android_id'], outcome: 'ok', value_hash: marker.value_sha256.slice(0, 16),
            observation_run: marker.run, fixture_batch: marker.batch, hook: KIND
          };
          // 后台只读/补传的新增强字段：旧字段不变，仅可选透传。
          if (typeof marker.origin === 'string') read.fixture_origin = marker.origin;
          if (typeof marker.thread === 'string') read.fixture_thread = marker.thread;
          log('PRIVACY_READ', read);
        } catch (error) {
          log('SCRIPT_ERROR', {where: TAG, msg: String(error)});
        }
      }
    });
    log('ARMED', {hooks: 1, hook: KIND});
  } catch (error) {
    log('SCRIPT_ERROR', {where: KIND, msg: String(error)});
  }
}
