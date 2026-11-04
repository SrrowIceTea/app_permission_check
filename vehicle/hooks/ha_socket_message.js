// 仅用于授权测试。Keep only protocol metadata and the isolated test entity.
const ENTITY = 'input_boolean.audit_test_light';
const TYPES = new Set(['subscribe_entities', 'get_states']);

export function decodeSocketText(text) {
  if (text.length > 64 * 1024) return null;
  try {
    const value = JSON.parse(text);
    return Array.isArray(value) ? value : [value];
  } catch (_) {
    return null;
  }
}

export function requestMetadata(message) {
  if (!validId(message) || !TYPES.has(message.type)) return null;
  if (message.entity_ids !== undefined &&
      (!Array.isArray(message.entity_ids) || !message.entity_ids.includes(ENTITY))) return null;
  return {message_id: message.id, command: message.type};
}

export function resultMetadata(message) {
  if (!validId(message) || message.type !== 'result' || typeof message.success !== 'boolean') return null;
  return {message_id: message.id, success: message.success};
}

export function entityState(message) {
  if (!validId(message) || message.type !== 'event') return null;
  const state = message.event?.c?.[ENTITY]?.['+']?.s;
  if (state !== 'on' && state !== 'off') return null;
  return {message_id: message.id, entity_id: ENTITY, state};
}

function validId(message) {
  return Number.isSafeInteger(message?.id) && message.id > 0;
}
