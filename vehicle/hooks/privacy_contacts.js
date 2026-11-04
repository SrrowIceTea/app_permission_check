// 仅用于授权测试。Track only returned contacts cursors; never query or move them.
import { describe } from '../../core/privacy/values.js';
import { describeException } from '../../core/privacy/dispatch.js';

export function contactTracker(emit, gap) {
  const identity = Java.use('java.util.IdentityHashMap').$new();
  const classes = new Set();
  const JObject = Java.use('java.lang.Object');
  return function track(cursor) {
    if (cursor === null) return;
    if (identity.size() >= 256) {
      gap('contacts_tracking_limit', '256 open cursors; further cursors are not classified');
      return;
    }
    const name = String(Java.cast(cursor, JObject).getClass().getName());
    if (!classes.has(name)) {
      try {
        const cls = Java.use(name), get = cls.getString.overload('int');
        get.implementation = function (column) {
          const monitored = identity.containsKey(this);
          let ret, error;
          try { ret = get.call(this, column); } catch (e) { error = e; }
          if (monitored) {
            try {
              const err = error ? describeException(error) : null;
              emit({data_type: 'contacts', api: 'android.database.Cursor.getString(I)Ljava/lang/String;',
                hook_class: name, capture: 'string'}, ret,
                err ? (err.denied ? 'denied' : 'error') : 'ok', err,
                error ? {} : describe(['contacts'], {}, ret));
            } catch (e) { gap('contacts_observation_failed', String(e)); }
          }
          if (error) throw error;
          return ret;
        };
        const close = cls.close.overload();
        close.implementation = function () {
          try { identity.remove(this); } catch (e) { gap('contacts_close_tracking_failed', String(e)); }
          return close.call(this);
        };
        classes.add(name);
      } catch (e) { gap('contacts_cursor_api_missing', name + ': ' + String(e)); return; }
    }
    identity.put(cursor, cursor);
  };
}
