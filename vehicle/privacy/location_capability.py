"""定位内容匹配的**能力边界**声明。仅用于授权测试；坐标均为合成数据。

把散落在 VEHICLE_LOCATION_CANONICAL_CAPTURE_20261110.md 表 E / §6、DECISIONS
L001/L002、observation_ledger UNSUPPORTED_LOCATION_FORMS 的能力边界收敛成**单一、
机器可核对**的契约。这里只声明"能比什么、不能比什么、为什么"，不产生候选、
finding 或规则结论；命中与否仍由 location_match.evaluate 决定。
"""
from __future__ import annotations

# 采集侧 privacy_location.js 实际产出的全部形态（7 种），与 FORM_NAMES 对齐。
HOOK_FORM_NAMES = (
    'pair_d6', 'pair_d6_lonlat', 'pair_raw', 'pair_raw_lonlat', 'geo_d6',
    'single_lat_d6', 'single_lon_d6',
)

# 消费侧接受为**主形态**的成对形态：误配预算约 1e-17。此处是单一来源，
# location_match.PAIR_FORMS 从这里导入，避免循环依赖与两处漂移。
PRIMARY_FORMS = ('pair_d6', 'pair_d6_lonlat', 'pair_raw', 'pair_raw_lonlat', 'geo_d6')

# 只作辅助佐证、绝不单独定论：误配预算约 1e-9（高 8 个数量级）。
SUPPORTING_FORMS = ('single_lat_d6', 'single_lon_d6')

# 明确不支持的形态 → 不支持理由。任何一项都**不是**"没有外发"。
REJECTED_FORMS = {
    # 前五项沿用 observation_ledger 原键名，保持下游断言/展示不变。
    'separate_lat_lon_numeric_fields':
        '数值叶子单独哈希不等于成对字符串；需在同条正文里配对，误配预算不可控',
    'geojson_or_nested_object':
        '嵌套对象/geohash/base64/hex 派生编码未生成，不能逐字节比对',
    'protobuf_or_binary_payload':
        '非 JSON 或 decode_error，哈希集合为空',
    'single_coordinate_only':
        '单值误配预算约 1e-9，比成对高 8 个数量级，只作佐证不作主形态',
    'precision_other_than_d6_whole_pair_string':
        '仅采集 6dp 与 Double.toString 两档，%.4f/%.7f/去尾零必然对不上',
    # 补充边界（文档表 E 已述，此前未进 ledger）。
    'whole_location_to_string':
        '叶子是 Location[gps ...] 整串，与规范形态不逐字节相同',
    'integer_microdegrees':
        '8 位整数通用性强、误配风险最高，故意不做',
}

FORMAT_CAPABILITY = {
    'schema_version': 1,
    'experimental_only': True,
    'emits_rule_findings': False,
    'hook_forms': list(HOOK_FORM_NAMES),
    'primary_forms': list(PRIMARY_FORMS),
    'supporting_forms': list(SUPPORTING_FORMS),
    'rejected_forms': dict(REJECTED_FORMS),
    'false_match_budget': {'pair': '1e-17', 'single': '1e-9'},
    'note': ('成对形态命中才产生 content_match_candidate；单值形态仅供已确认配对'
             '作辅助佐证，不单独定论。未命中一律是"本方法未观测到"，不是"没有外发"。'),
}


def capability_snapshot() -> dict:
    """返回可被 JSON 序列化、调用方改动不影响内部常量的能力快照。"""
    return {
        'schema_version': FORMAT_CAPABILITY['schema_version'],
        'primary_forms': list(PRIMARY_FORMS),
        'supporting_forms': list(SUPPORTING_FORMS),
        'rejected_forms': dict(REJECTED_FORMS),
        'false_match_budget': dict(FORMAT_CAPABILITY['false_match_budget']),
        'note': FORMAT_CAPABILITY['note'],
    }
