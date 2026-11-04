// 仅用于授权测试。Persist only the allowlisted battery field or test-entity control metadata.
const ENTITY = 'input_boolean.audit_test_light';
const SERVICES = new Set(['turn_on', 'turn_off', 'toggle']);

export function webhookSummary(text) {
  let payload;
  try {
    payload = JSON.parse(text);
  } catch (_) {
    return {gap: 'invalid_json'};
  }
  if (payload?.type === 'update_sensor_states') return battery(payload);
  if (payload?.type === 'call_service') return control(payload);
  return {};
}

function battery(payload) {
  if (!Array.isArray(payload.data)) return {gap: 'unexpected_sensor_schema'};
  const matches = payload.data.filter(row => row?.unique_id === 'battery_level');
  if (matches.length === 0) return {};
  const value = matches[0].state;
  if (matches.length !== 1 || !Number.isInteger(value) || value < 0 || value > 100) {
    return {gap: 'ambiguous_or_invalid_battery_state'};
  }
  return {kind: 'sensor', state: value};
}

function control(payload) {
  const data = payload.data;
  if (!data || typeof data.domain !== 'string' || !SERVICES.has(data.service)) {
    return {gap: 'unexpected_control_schema'};
  }
  // Other entities stay unobserved rather than entering the evidence log.
  if (data.service_data?.entity_id !== ENTITY) return {};
  if (data.domain !== 'input_boolean') return {gap: 'unexpected_control_schema'};
  return {kind: 'control', payload_type: 'call_service', domain: data.domain,
    service: data.service, operation: data.domain + '.' + data.service, entity_id: ENTITY};
}
