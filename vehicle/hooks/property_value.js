// Authorized tests only. Extract serializable values without changing the return.
export function propertyValue(value, formatDisplay) {
  try {
    if (value === null || value === undefined) return { value_raw: null };
    let unwrapped = value;
    const wrapped = value.$className === 'android.car.hardware.CarPropertyValue';
    if (wrapped) {
      const status = value.getStatus();
      if (status !== 0) return formatDisplay
        ? { value_raw: null, value_status: status, value: 'CarPropertyValue{status=' + status + ',value=null}' }
        : { value_raw: null, value_status: status };
      unwrapped = value.getValue();
    }
    let result;
    const type = typeof unwrapped;
    if (unwrapped === null) result = { value_raw: null };
    else if (type === 'number' || type === 'boolean' || type === 'string')
      result = { value_raw: unwrapped, value_type: type };
    else {
      const name = String(unwrapped.$className || 'java.lang.Object');
      result = name.startsWith('[') ? { value_capture_gap: 'array_value_not_supported' }
        : { value_raw: String(unwrapped), value_type: name };
    }
    if (formatDisplay) {
      const display = result.value_capture_gap ? formatDisplay(unwrapped) : String(result.value_raw);
      result.value = wrapped ? 'CarPropertyValue{status=0,value=' + display + '}' : display;
    }
    return result;
  } catch (e) { return { value_capture_gap: String(e) }; }
}
