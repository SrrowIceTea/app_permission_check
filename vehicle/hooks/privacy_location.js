// 仅用于授权测试（自有设备与自有 APK）。
// 车载定位返回值 → 可与「出站 JSON 字符串叶子」比较的规范形态。
//
// 不保留原文（vehicle/privacy/POLICY.md）：本文件只输出规范形态的 SHA-256 前 16 hex
// 与其字符长度，从不输出经纬度本身。观察不改写：只读已返回 Location 的字段，
// 不额外请求定位、不改返回值、不向外抛异常（钩子记录失败不得影响被测应用）。
//
// 为什么需要「规范形态」：求值器只比对**字符串叶子**的 SHA-256 前 16 hex，
// 所以能不能匹配取决于"我们生成的字符串"与"应用发出去的字符串"是否逐字节相同。
// 这里把同一组经纬度按**有限几种**真实 SDK 常见编码各生成一份哈希，供离线评估
// 逐形态量化召回与误配；`value_hash` 只取其中一种（主形态），其余仅作证据留存。
import { sha256hex16 } from '../../core/privacy/values.js';

// 6 位小数：第三方 SDK 最常用的 "%.6f" 编码，也覆盖高德/百度的 lng,lat 顺序。
const DECIMALS = 6;

function d6 (value) { return value.toFixed(DECIMALS); }

// 形态表是唯一来源：顺序 = 文档表格顺序 = 离线评估顺序，第 0 项为主形态。
// 只放**无损**形态（全部 6 位小数或 Double.toString 全精度），不收任何取整/量化编码。
const FORMS = [
  ['pair_d6', (lat, lon) => d6(lat) + ',' + d6(lon)],
  ['pair_d6_lonlat', (lat, lon) => d6(lon) + ',' + d6(lat)],
  ['pair_raw', (lat, lon) => String(lat) + ',' + String(lon)],
  ['pair_raw_lonlat', (lat, lon) => String(lon) + ',' + String(lat)],
  ['geo_d6', (lat, lon) => 'geo:' + d6(lat) + ',' + d6(lon)],
  ['single_lat_d6', (lat) => d6(lat)],
  ['single_lon_d6', (lat, lon) => d6(lon)]
];

export const LOCATION_FORM_NAMES = FORMS.map(([name]) => name);

// 唯一无法穷尽的部分：应用可能用别的精度（%.4f/%.7f）、别的数值格式（科学计数法、
// 去掉尾零）或派生编码（geohash/base64/hex/protobuf）。这些形态这里不生成。
export const LOCATION_CAPTURE_GAP =
  'location canonical encodings only: numeric JSON leaves, other decimal precisions, ' +
  'scientific notation, geohash/base64/hex and non-JSON bodies stay incomparable';

function formList (lat, lon) {
  const out = [];
  for (const [form, build] of FORMS) {
    let text;
    try { text = build(lat, lon); } catch (e) { continue; }  // 某形态生成失败不拖垮其它形态
    const hash = sha256hex16(text);
    if (typeof hash === 'string' && hash.length === 16) out.push({ form, len: text.length, hash });
  }
  return out;
}

function unusableFix (fix, gap) {
  // 保持与旧证据一致的读取状态语义（non_empty → obtained），只是**不出可匹配哈希**：
  // 给 0,0 或越界坐标算哈希等于造一个高频误配源。
  return { collection_state: 'obtained', non_empty: true, location_fix: fix, value_capture_gap: gap };
}

export function locationEvidence (ret) {
  if (ret === null || ret === undefined) return { collection_state: 'empty', non_empty: false };
  let lat, lon;
  try {
    lat = Number(ret.getLatitude());
    lon = Number(ret.getLongitude());
  } catch (e) {
    // 字段读不到 ≠ 没定位：如实标 unknown，不猜成 empty。
    return { collection_state: 'unknown', location_capture_gap: 'location_fields_unreadable' };
  }
  if (!Number.isFinite(lat) || !Number.isFinite(lon)) {
    return { collection_state: 'unknown', location_capture_gap: 'location_coordinate_not_finite' };
  }
  if (Math.abs(lat) > 90 || Math.abs(lon) > 180) {
    return unusableFix('out_of_range', 'coordinate out of range; no hash emitted');
  }
  if (lat === 0 && lon === 0) {
    // Android 在无定位时返回 (0,0)；它不是几内亚湾的真坐标，且 6 位小数的零对
    // 在出站正文里极其常见，算哈希只会制造误配。
    return unusableFix('zero_pair_unverified', 'zero pair is not a verified fix; no hash emitted');
  }
  const forms = formList(lat, lon);
  const primary = forms.length ? forms[0] : null;
  if (!primary) {
    return unusableFix('unhashable', 'canonical encoding failed; no hash emitted');
  }
  return {
    collection_state: 'obtained',
    non_empty: true,
    value_len: primary.len,
    value_hash: primary.hash,
    value_kind: 'location_pair',
    location_form: primary.form,
    location_precision: DECIMALS,
    location_forms: forms,
    value_capture_gap: LOCATION_CAPTURE_GAP
  };
}
