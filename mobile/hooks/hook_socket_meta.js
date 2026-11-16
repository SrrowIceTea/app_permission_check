// 仅用于授权测试。记录白名单进程的 socket 端点与时间，不读取报文正文。
import { parseSockaddr } from './hook_egress_tp.js';
import { packages } from './scope.js';
import { makeLogger, procName } from './runtime.js';

const log = makeLogger('socket_meta', '/data/local/tmp/vscan-mobile.log');
const TYPE = /^(tcp|udp)[46]?$/;

function address(pointer) {
  return pointer && !pointer.isNull() ? parseSockaddr(pointer) : null;
}

export function main() {
  try { arm(); }
  catch (error) { log('SOCKET_META_ERROR', { operation: 'arm', error: String(error) }); }
}

function arm() {
  const pkg = procName();
  if (!packages().includes(pkg)) return;
  const uid = Java.use('android.os.Process').myUid();
  const libc = Process.getModuleByName('libc.so');
  let errorLogged = false;
  const errors = name => error => {
    if (!errorLogged) log('SOCKET_META_ERROR', { operation: name, error: String(error) });
    errorLogged = true;
  };
  const specs = [
    ['connect', 'connect', args => address(args[1])],
    ['send', 'send', () => null],
    ['sendto', 'send', args => address(args[4])],
    ['sendmsg', 'send', args => address(args[1].readPointer())],
    ['recvfrom', 'recv', args => args[4]],
    ['recvmsg', 'recv', args => args[1].readPointer()],
  ];
  const armed = [];
  for (const [name, operation, readPeer] of specs) {
    try {
      const fn = libc.findExportByName(name);
      if (fn === null) {
        log('SOCKET_META_MISSING', { operation: name });
        continue;
      }
      const onError = errors(name);
      Interceptor.attach(fn, {
        onEnter(args) {
          const errno = this.errno;
          try {
            this.fd = args[0].toInt32();
            this.peer = readPeer(args);
            this.started = Date.now();
          } catch (error) { onError(error); }
          finally { this.errno = errno; }
        },
        onLeave(result) {
          if (this.started === undefined) return;
          const errno = this.errno;
          const rc = result.toInt32();
          if (rc < 0 && !(operation === 'connect' && errno === 115)) return;
          const ended = Date.now();
          try {
            const socketType = Socket.type(this.fd);
            const type = socketType && TYPE.exec(socketType);
            if (!type || (operation !== 'connect' && type[1] !== 'udp')) return;
            let peer = operation === 'recv' ? address(this.peer) : this.peer;
            if (!peer) {
              const connected = Socket.peerAddress(this.fd);
              if (connected) peer = { ip: connected.ip, port: connected.port };
            }
            const local = Socket.localAddress(this.fd);
            if (!peer || !local || !local.port || !peer.port) return;
            log('SOCKET_META', { package: pkg, uid, fd: this.fd, operation, transport: type[1],
              local_ip: local.ip, local_port: local.port, remote_ip: peer.ip, remote_port: peer.port,
              started_ms: this.started, ended_ms: ended });
          } catch (error) { onError(error); }
          finally { this.errno = errno; }
        }
      });
      armed.push(name);
    } catch (error) { errors(name)(error); }
  }
  log('ARMED', { hooks: armed, uid });
}
