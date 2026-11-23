package com.vscanner.rules

/**
 * Non-negotiable constants describing the rule database this build is supposed to
 * ship. Taken from rules_library/rules.db.summary.json - never adjusted to make a
 * failing check pass.
 *
 * The versions come from different places and that distinction is load-bearing:
 * "13" is extracted from AOSP android-13.0.0_r1, "14" from android-14.0.0_r1 and
 * "16" from android-16.0.0_r1; "15" is observed on the API 35 test device (146 car
 * permissions read off `pm list permissions -f`, plus four generic Android permissions
 * from the same frozen output; VHAL ids and CPM signatures read off the device's own
 * android.car.jar). Device observations are definition_status=pending and must
 * never be reported as source extractions.
 *
 * 13/14/16 carry the same four generic privacy permissions, but each from its own
 * frameworks/base core/res/AndroidManifest.xml at the locked release commit - never
 * borrowed from the API 35 device.
 *
 * enabledRules counts the rules actually approved to produce audit conclusions. It is
 * asserted so that an accidental enable or disable is noticed.
 *
 * 14/15 enable all 29 rules per version (22 VHAL rules calibrated to 30000ms plus seven
 * general-privacy rules). 13/16 have no egress-window calibration, so their ten
 * data_egress rules stay disabled: 19 enabled per version.
 * See EGRESS_CALIBRATION.md (2026-09-24 user authorization) and vehicle/privacy/POLICY.md.
 *
 * 仅供授权测试。本对象原在 RulesVerifier.kt 内，2026-11-10 为单文件 ≤300 行原样搬出
 * （同 package 的顶层声明，引用处一字未改）。
 */
object BaselineExpectation {
    const val SHA256 = "ea0ec53c95a6d0edd91e38083f00a1cda024537db4c23074c6481eb0d3cf6c18"
    const val SOURCE_TAG = "13/14/16=AOSP release source / 15=设备实测 API 35"

    val VERSIONS: Map<String, VersionCounts> = mapOf(
        "13" to VersionCounts(
            permissions = 10,
            vhalProperties = 8,
            dangerousApis = 3,
            // 22 VHAL rules + 5 VSC-GR + 2 VSC-GE general-privacy rules.
            riskRules = 29,
            // The ten data_egress rules stay disabled: no window calibration for 13.
            enabledRules = 19,
        ),
        "14" to VersionCounts(
            permissions = 10,
            vhalProperties = 8,
            dangerousApis = 3,
            // 22 VHAL rules + 5 VSC-GR + 2 VSC-GE general-privacy rules.
            riskRules = 29,
            enabledRules = 29,
        ),
        "15" to VersionCounts(
            permissions = 150,
            vhalProperties = 8,
            dangerousApis = 3,
            // The nine policy drafts are mirrored here. Their basis_refs (POLICY.md) is
            // version-independent project policy and carried over unchanged; their
            // source_refs were replaced with device observations, because the AOSP
            // android-14 citations do not describe this release. DECISIONS D009.
            riskRules = 29,
            enabledRules = 29,
        ),
        "16" to VersionCounts(
            permissions = 10,
            vhalProperties = 8,
            dangerousApis = 3,
            // 22 VHAL rules + 5 VSC-GR + 2 VSC-GE general-privacy rules.
            riskRules = 29,
            // The ten data_egress rules stay disabled: no window calibration for 16.
            enabledRules = 19,
        ),
    )
}
