package com.pishi.ifoxy.widget

import android.content.Context
import java.util.UUID

/**
 * SEC-FX-02: the widget provider is exported (Android requires it), so any
 * installed app could previously broadcast ACTION_TOGGLE_VPN and start/stop
 * the user's VPN. The toggle intent now carries a per-install random token
 * that only this app can mint (it lives in the app's private preferences);
 * broadcasts without the matching token are ignored.
 */
object WidgetToggleGuard {
    private const val PREFS_NAME = "ifoxy_widget_guard"
    private const val KEY_TOKEN = "toggle_token"
    const val EXTRA_TOGGLE_TOKEN = "com.pishi.ifoxy.extra.TOGGLE_TOKEN"

    @Synchronized
    fun token(context: Context): String {
        val prefs = context.applicationContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        prefs.getString(KEY_TOKEN, null)?.takeIf { it.isNotBlank() }?.let { return it }
        val minted = UUID.randomUUID().toString()
        prefs.edit().putString(KEY_TOKEN, minted).apply()
        return minted
    }

    fun isAuthorized(context: Context, presented: String?): Boolean {
        if (presented.isNullOrBlank()) return false
        val expected = token(context)
        // Constant-time comparison; the token is a capability, not a password,
        // but there is no reason to offer a timing oracle for it either.
        if (presented.length != expected.length) return false
        var diff = 0
        for (i in expected.indices) diff = diff or (expected[i].code xor presented[i].code)
        return diff == 0
    }
}
