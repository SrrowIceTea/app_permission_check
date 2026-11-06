// 仅用于授权测试。Observe successful Chromium writes in the pinned MG4 process.
import { packages } from './scope.js';
import { decodeUtf8, makeLogger, procName } from './vscan_runtime.js';
import { formWrite } from './mg4_form_write.js';

const PKG = 'com.tommasov.mg4browser';
const CALLER = 'libwebviewchromium.so';
const log = makeLogger('http_write', '/data/local/tmp/vscan-mg4-send.log');

export function armNativeForm(identity) {
  if (procName() !== PKG || !packages().includes(PKG)) return;
  try {
    Interceptor.attach(Process.getModuleByName('libc.so').getExportByName('sendto'), {
      onEnter(args) {
        const saved = this.errno;
        try {
          if (Process.findModuleByAddress(this.returnAddress)?.name !== CALLER
              || args[1].isNull() || args[2].compare(ptr(4096)) > 0) return;
          const fd = args[0].toInt32();
          if (!['tcp', 'tcp6'].includes(Socket.type(fd))) return;
          const peer = Socket.peerAddress(fd), local = Socket.localAddress(fd);
          if (peer?.ip !== '127.0.0.1' || peer.port !== 8888 || !local?.port) return;
          const size = args[2].toUInt32();
          if (!size || args[1].readU8() !== 0x50) return;
          const form = formWrite(decodeUtf8(new Uint8Array(args[1].readByteArray(size))));
          if (!form) return;
          this.observation = {...identity, method: 'POST', scheme: 'http', host: form.host,
            port: form.port, path: form.path, body_sha256: Checksum.compute('sha256', form.body),
            body_bytes: form.body.length, write_bytes: size, fd, local_port: local.port,
            peer_host: peer.ip, peer_port: peer.port, caller: CALLER, api: 'sendto',
            device_start_ms: Date.now()};
        } catch (_) { log('ERROR', {...identity, where: 'mg4_send_enter'}); }
        finally { this.errno = saved; }
      },
      onLeave(value) {
        if (!this.observation) return;
        const saved = this.errno;
        try {
          const count = value.toInt32();
          log(count === this.observation.write_bytes ? 'HTTP_WRITE' : 'HTTP_WRITE_INCOMPLETE',
            {...this.observation, returned_bytes: count, device_end_ms: Date.now()});
        } catch (_) { log('ERROR', {...identity, where: 'mg4_send_leave'}); }
        finally { this.errno = saved; }
      },
    });
    log('ARMED', {...identity, caller: CALLER, api: 'sendto'});
  } catch (_) { log('ERROR', {...identity, where: 'mg4_send_arm'}); }
}
