// Authorized tests only. Extract serializable values without changing the return.
export function propertyValue(value) {
  try {
    if (value === null || value === undefined) return { value_raw: null };
    let unwrapped = value;
    if (value.$className === 'android.car.hardware.CarPropertyValue') {
      if (value.getStatus() !== 0) return { value_raw: null, value_status: value.getStatus() };
      unwrapped = value.getValue();
    }
    if (unwrapped === null) return { value_raw: null };
    if (['number', 'boolean', 'string'].includes(typeof unwrapped)) {
      return { value_raw: unwrapped, value_type: typeof unwrapped };
    }
    const name = String(unwrapped.$className || 'java.lang.Object');
    if (name.startsWith('[')) return { value_capture_gap: 'array_value_not_supported' };
    return { value_raw: String(unwrapped), value_type: name };
  } catch (e) { return { value_capture_gap: String(e) }; }
}
