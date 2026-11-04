// 仅用于授权测试。 Collapse only synchronous, same-property CPM delegates.
const DIRECT = 'cpm.getProperty(II)';
const TYPED = 'cpm.getProperty(Class,II)';
const SCALAR = new Set(['cpm.getFloatProperty(II)', 'cpm.getIntProperty(II)', 'cpm.getBooleanProperty(II)']);

export function createReadScope() {
  const active = new Map();
  return {
    enter(thread, api, property, area) {
      const parent = active.get(thread);
      if (parent && parent.property === property && parent.area === area && !parent.delegates.has(api) &&
          ((api === DIRECT && (parent.api === TYPED || SCALAR.has(parent.api))) ||
           (api === TYPED && SCALAR.has(parent.api)))) {
        parent.delegates.add(api);
        parent.nested_suppressed++;
        return { merged: true, outer: parent };
      }
      const frame = { thread, api, property, area, parent, nested_suppressed: 0,
                      delegate: null, delegates: new Set() };
      active.set(thread, frame);
      return frame;
    },
    leave(frame) {
      if (frame.merged) return;
      if (frame.parent) active.set(frame.thread, frame.parent);
      else active.delete(frame.thread);
    }
  };
}

export function recordDelegate(outer, api, outcome) {
  if (api === DIRECT || outer.delegate === null) outer.delegate = outcome;
}
