package com.vscanner.targetapp

// 仅用于授权测试。Owned fixture consent UI; not a model of arbitrary third-party UI.
import android.app.Activity
import android.os.Bundle
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView

class AuditConsentActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val state = AuditScenarioState(this)
        val panel = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        val status = TextView(this).apply { text = "Audit consent: ${state.consent()}" }
        panel.addView(status)
        for ((label, value) in listOf("Grant audit consent" to "granted", "Withdraw audit consent" to "revoked")) {
            panel.addView(Button(this).apply {
                text = label
                setOnClickListener {
                    state.setConsent(value)
                    status.text = "Audit consent: ${state.consent()}"
                }
            })
        }
        setContentView(panel)
    }
}
