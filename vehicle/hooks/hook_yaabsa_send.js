// 仅用于授权测试。Observe the pinned APK's Cronet writes to isolated ABS.
import './java_bootstrap.js';
import { packages } from './scope.js';
import { decodeUtf8, makeLogger, procName } from './vscan_runtime.js';
import { syncBody } from './abs_sync_body.js';

const PKG = 'de.vito0912.yaabsa';
const CALLER = 'libcronet.147.0.7727.49.so';
const MAX_WRITE = 4096;
const log = makeLogger('abs_native_send', '/data/local/tmp/vscan-abs-native-send.log');
const loopback = addr => addr && ['127.0.0.1', '::ffff:127.0.0.1', '::ffff:7f00:1'].includes(addr.ip);

Java.perform(() => {
  if (procName() !== PKG || !packages().includes(PKG)) return;
  try {
    const uid = Number(Java.use('android.os.Process').myUid());
    const identity = {pkg: PKG, uid, user_id: Math.floor(uid / 100000)};
    const libc = Process.getModuleByName('libc.so');
    const api = 'sendto';
    const address = libc.getExportByName(api);
    Interceptor.attach(address, {
        onEnter(args) {
          const savedErrno = this.errno;
          try {
            const caller = Process.findModuleByAddress(this.returnAddress)?.name;
            if (caller !== CALLER || args[1].isNull() || args[2].compare(ptr(MAX_WRITE)) > 0) return;
            const fd = args[0].toInt32();
            if (!['tcp', 'tcp6'].includes(Socket.type(fd))) return;
            const peer = Socket.peerAddress(fd);
            if (!loopback(peer) || peer.port !== 18125) return;
            const local = Socket.localAddress(fd);
            if (!loopback(local) || !local.port) return;
            const size = args[2].toUInt32();
            if (!size || ![0x7b, 0x50].includes(args[1].readU8())) return;
            const parsed = syncBody(decodeUtf8(new Uint8Array(args[1].readByteArray(size))));
            if (!parsed) return;
            this.observation = {...identity, api, caller, fd, local_port: local.port,
              peer_host: '127.0.0.1', peer_port: peer.port, write_size: size, device_start_ms: Date.now(),
              body_sha256: Checksum.compute('sha256', parsed.text), body_bytes: parsed.text.length,
              abs_session_id: parsed.session};
          } catch (_) {
            log('ERROR', {...identity, where: 'abs_native_send_observe'});
          } finally {
            this.errno = savedErrno;
          }
        },
        onLeave(retval) {
          if (!this.observation) return;
          const savedErrno = this.errno;
          try {
            const count = retval.toInt32();
            log(count === this.observation.write_size ? 'ABS_SYNC_WRITE' : 'ABS_SYNC_WRITE_INCOMPLETE',
                {...this.observation, returned_bytes: count, device_end_ms: Date.now()});
          } catch (_) {
            log('ERROR', {...identity, where: 'abs_native_send_result'});
          } finally {
            this.errno = savedErrno;
          }
        },
    });
    log('ARMED', {...identity, apis: [api], caller: CALLER, endpoint: 'isolated_abs_loopback'});
  } catch (_) {
    log('ERROR', {pkg: PKG, where: 'abs_native_send_arm'});
  }
});
