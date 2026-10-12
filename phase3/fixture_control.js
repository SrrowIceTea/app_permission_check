// 仅用于授权测试：触发两个自有夹具的已有按钮，不属于审计 Hook。
import Java from 'frida-java-bridge';
rpc.exports = {
  click(name, endpoint) {
    if (!['btnRead', 'btnEgressHttp', 'btnOkHttp'].includes(name)) throw new Error('unsupported test button');
    if (endpoint && endpoint !== 'http://127.0.0.1:8888/collect') throw new Error('local test endpoint only');
    return new Promise((resolve, reject) => Java.perform(() => {
      const app = Java.use('android.app.ActivityThread').currentApplication();
      const pkg = String(app.getPackageName());
      if (!['com.vscanner.targetapp', 'com.vscanner.targetapp2'].includes(pkg)) {
        reject(new Error('self-owned fixtures only')); return;
      }
      let found = false;
      Java.choose(pkg + '.MainActivity', {
        onMatch(activity) {
          if (found || activity.isDestroyed()) return;
          found = true;
          const retained = Java.retain(activity);
          Java.scheduleOnMainThread(() => {
            let stage = 'resources';
            try {
              const base = Java.cast(retained, Java.use('android.app.Activity'));
              const resources = Java.cast(base.getResources(), Java.use('android.content.res.Resources'));
              if (endpoint) {
                const field = Java.cast(base.findViewById(resources.getIdentifier('etHttpEndpoint', 'id', pkg)),
                                        Java.use('android.widget.EditText'));
                field.setText.overload('java.lang.CharSequence', 'android.widget.TextView$BufferType')
                  .call(field, Java.use('java.lang.String').$new(endpoint),
                        Java.use('android.widget.TextView$BufferType').EDITABLE.value);
              }
              const id = resources.getIdentifier(name, 'id', pkg);
              stage = 'findViewById';
              const button = Java.cast(base.findViewById(id), Java.use('android.view.View'));
              stage = 'performClick';
              if (!button || !button.performClick()) throw new Error('button not clicked');
              resolve({ package: pkg, button: name, device_ts: Date.now() });
            } catch (e) { reject(new Error(stage + ': ' + String(e.stack || e))); }
            finally { retained.$dispose(); }
          });
        },
        onComplete() { if (!found) reject(new Error('fixture Activity absent')); }
      });
    }));
  }
};
