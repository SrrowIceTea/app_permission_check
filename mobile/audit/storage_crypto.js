// 仅用于授权测试：宿主显式白名单；默认仅自有夹具；只观察，不改返回或异常。
import Java from 'frida-java-bridge';

const DEFAULT_PACKAGE = 'com.vscanner.privacydemo';
const MAX_BYTES = 256, MAX_CHARS = 256;
const busy = new Set();
let pkg = null, sequence = 0, objectSequence = 0, retries = 0, activated = false;

function emit(ev, extra = {}) {
  try {
    const rec = { ...extra, ev, ts: Date.now(), pkg, src: 'storage_crypto',
      pid: Process.id, tid: Process.getCurrentThreadId(), evt_id: ++sequence };
    // Direct structured payload plus the existing PC driver's compatible envelope.
    send({ ...rec, line: JSON.stringify(rec) });
  } catch (_) { /* Never write device files, console, or alter app behavior. */ }
}

function observed(original, after) {
  const tid = Process.getCurrentThreadId();
  if (busy.has(tid)) return original();
  busy.add(tid);
  try {
    const result = original(); // Exceptions propagate unchanged; no success event.
    try { after(result); }
    catch (error) { emit('OBSERVATION_ERROR', { error: String(error).slice(0, 300) }); }
    return result;
  } finally { busy.delete(tid); }
}

function text(value, limit = MAX_CHARS) {
  if (value === null) return { chars: 0, text: null, truncated: false };
  const s = String(value);
  return { chars: s.length, text: s.slice(0, limit), truncated: s.length > limit };
}

function bytes(array, offset = 0, length = array === null ? 0 : array.length) {
  if (array === null) return { len: 0, captured: 0, hex: '', truncated: false };
  const n = Math.min(length, MAX_BYTES);
  let hex = '';
  for (let i = 0; i < n; i++) hex += (array[offset + i] & 255).toString(16).padStart(2, '0');
  return { len: length, captured: n, hex, truncated: length > n };
}

function install(app) {
  const WeakMap = Java.use('java.util.WeakHashMap');
  const JString = Java.use('java.lang.String');
  const File = Java.use('java.io.File');
  const Digest = Java.use('java.security.MessageDigest');
  const ciphers = WeakMap.$new(), streams = WeakMap.$new();
  const root = String(File.$new(String(app.getApplicationInfo().dataDir.value)).getCanonicalPath());
  const armed = [], missing = [];
  const gaps = [
    'SharedPreferences.putString stages edits only; commit/apply and disk contents unverified',
    'FileOutputStream only: app dataDir paths, four path constructors, write(byte[]) and write(byte[],int,int)',
    'No FileDescriptor constructor, write(int), native IO, SQLite, external or device-protected storage',
    'Cipher.init overloads and exact doFinal(byte[]) only; no update/other doFinal/native crypto',
    'Byte/text previews bounded to 256; concurrent mutation and unseen calls may hide data',
    'Host must attach to the authorized process; supports root Frida Server or embedded Gadget'
  ];

  function hook(label, overload, implementation) {
    try { overload.implementation = implementation(overload); armed.push(label); }
    catch (error) { missing.push(label); emit('HOOK_MISS', { target: label, error: String(error) }); }
  }
  function attempt(label, work) {
    try { work(); }
    catch (error) { missing.push(label); emit('HOOK_MISS', { target: label, error: String(error) }); }
  }
  function put(map, key, value) { map.put(key, JString.$new(JSON.stringify(value))); }
  function get(map, key) { const v = map.get(key); return v === null ? null : JSON.parse(String(v)); }

  attempt('SharedPreferences.EditorImpl.putString', () => {
    const Editor = Java.use('android.app.SharedPreferencesImpl$EditorImpl');
    hook('SharedPreferences.EditorImpl.putString', Editor.putString.overload(
      'java.lang.String', 'java.lang.String'), ov => function (key, value) {
      return observed(() => ov.call(this, key, value), () => emit('PREF_PUT_STRING', {
        key: text(key, 128), value: text(value), success: true,
        observation_scope: 'editor_staged', disk_plaintext_proven: false
      }));
    });
  });

  attempt('Cipher.init', () => {
    const Cipher = Java.use('javax.crypto.Cipher');
    for (const ov of Cipher.init.overloads) {
      const signature = ov.argumentTypes.map(t => t.className).join(',');
      hook('Cipher.init(' + signature + ')', ov, original => function (...args) {
        return observed(() => original.apply(this, args), () => {
          // Real init argument, not nonexistent Cipher.getOpMode(). Never inspect key material.
          const iv = this.getIV();
          const metadata = { cipher_id: 'c' + (++objectSequence), opmode: Number(args[0]),
            algorithm: String(this.getAlgorithm()), iv_len: iv === null ? 0 : iv.length,
            iv_sha256_16: iv === null ? null : bytes(Digest.getInstance('SHA-256').digest(iv)).hex.slice(0, 16) };
          put(ciphers, this, metadata);
          emit('CIPHER_INIT', { ...metadata, signature, success: true });
        });
      });
    }
    hook('Cipher.doFinal([B)', Cipher.doFinal.overload('[B'), ov => function (input) {
      return observed(() => ov.call(this, input), output => {
        const state = get(ciphers, this) || { cipher_id: null, opmode: null,
          algorithm: String(this.getAlgorithm()) };
        const roles = state.opmode === 1 ? ['plaintext', 'ciphertext'] :
          state.opmode === 2 ? ['ciphertext', 'plaintext'] : ['unknown', 'unknown'];
        emit('CIPHER_FINAL', { ...state, signature: '([B)[B', success: true,
          input_role: roles[0], output_role: roles[1], input: bytes(input), output: bytes(output) });
      });
    });
  });

  attempt('FileOutputStream', () => {
    const Stream = Java.use('java.io.FileOutputStream');
    for (const types of [['java.lang.String'], ['java.lang.String', 'boolean'],
      ['java.io.File'], ['java.io.File', 'boolean']]) {
      const label = 'FileOutputStream.$init(' + types.join(',') + ')';
      attempt(label, () => hook(label, Stream.$init.overload(...types), ov => function (...args) {
        return observed(() => ov.apply(this, args), () => {
          const file = types[0] === 'java.lang.String' ? File.$new(args[0]) : args[0];
          const path = String(file.getCanonicalPath());
          if (!path.startsWith(root + '/')) return;
          const info = { stream_id: 'f' + (++objectSequence), path: text(path, 1024),
            append: types.length === 2 ? Boolean(args[1]) : false };
          put(streams, this, info);
          emit('FILE_OPEN', { ...info, success: true });
        });
      }));
    }
    for (const types of [['[B'], ['[B', 'int', 'int']]) {
      const label = 'FileOutputStream.write(' + types.join(',') + ')';
      attempt(label, () => hook(label, Stream.write.overload(...types), ov => function (...args) {
        return observed(() => ov.apply(this, args), () => {
          const info = get(streams, this);
          if (info === null) return; // Pre-attach/descriptor-only streams remain unknown.
          const offset = types.length === 1 ? 0 : Number(args[1]);
          const length = types.length === 1 ? args[0].length : Number(args[2]);
          emit('FILE_WRITE', { ...info, success: true, signature: '(' + types.join(',') + ')',
            array_offset: offset, bytes: bytes(args[0], offset, length),
            observation_scope: 'successful_stream_write', disk_plaintext_proven: false });
        });
      }));
    }
  });
  emit('ARMED', { hooks: armed, missing, coverage_gaps: gaps, max_bytes: MAX_BYTES,
    max_chars: MAX_CHARS, app_data_dir: root });
}

function allowedPackages() {
  const configured = globalThis.__VSCAN_AUDIT_PACKAGES__;
  if (configured === undefined) return [DEFAULT_PACKAGE];
  if (!Array.isArray(configured) || configured.length === 0 ||
      !Array.from(configured).every(p => typeof p === 'string' && /^[A-Za-z]\w*(?:\.\w+)+$/.test(p))) {
    throw new Error('Audit package whitelist must be a nonempty array of exact valid package names');
  }
  return [...configured];
}

function identity(app, context) {
  // Some Application subclasses return "" during attach; the supplied base Context
  // already has the actual identity. Never substitute the configured whitelist.
  const candidates = [context];
  try { if (app !== null) candidates.push(app.getBaseContext()); } catch (_) { /* Not attached yet. */ }
  candidates.push(app);
  for (const candidate of candidates) {
    if (candidate === null || candidate === undefined) continue;
    try {
      const name = candidate.getPackageName();
      if (name !== null && String(name).length > 0) return { context: candidate, name: String(name) };
    } catch (_) { /* A later bounded boot attempt can resolve the Context. */ }
  }
  return null;
}

function activate(app, context = null) {
  if (activated) return;
  const allowed = allowedPackages();
  const actual = identity(app, context);
  if (actual === null) return; // Transient empty identity is not an outside-whitelist verdict.
  pkg = actual.name;
  activated = true; // Exactly one install/skip, including a partially failed install.
  if (!allowed.includes(pkg)) { emit('SKIP', { reason: 'outside explicit audit whitelist' }); return; }
  emit('START', { whitelist: allowed, device_logging: false });
  install(actual.context);
}

function bootstrap() {
  try {
    if (typeof Java.performNow !== 'function') return;
    Java.performNow(() => {
      allowedPackages(); // Reject bad host configuration before installing even the bootstrap.
      const Application = Java.use('android.app.Application');
      // Hidden attach is absent from SDK stubs: derive its signature from the live VM.
      const candidates = Application.attach.overloads.filter(ov =>
        ov.argumentTypes.length === 1 && ov.argumentTypes[0].className === 'android.content.Context' &&
        ov.returnType.className === 'void');
      if (candidates.length !== 1) throw new Error('No unique runtime Application.attach(Context):void');
      const original = candidates[0];
      original.implementation = function (context) {
        return observed(() => original.call(this, context), () => activate(this, context));
      };
      emit('BOOTSTRAP_ARMED', { target: 'android.app.Application.attach',
        argument_types: original.argumentTypes.map(t => t.className),
        return_type: original.returnType.className, signature_source: 'runtime_enumerated_not_sdk_stub' });
    });
  } catch (error) { emit('HOOK_MISS', { target: 'Application.attach bootstrap', error: String(error) }); }
}

function boot() {
  Java.perform(() => {
    try {
      if (activated) return;
      allowedPackages();
      const app = Java.use('android.app.ActivityThread').currentApplication();
      if (app !== null) activate(app);
      if (!activated) {
        if (++retries <= 100) setTimeout(boot, 100);
        else emit('NOT_READY', { reason: 'Application or package identity unavailable after bounded retries' });
      }
    } catch (error) { emit('PROBE_ERROR', { error: String(error).slice(0, 400) }); }
  });
}
bootstrap();
boot();
