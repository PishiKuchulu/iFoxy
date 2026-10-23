package com.pishi.ifoxy.data

import android.content.Context
import com.pishi.ifoxy.data.model.RuntimeAuth

private const val TAG = "TokenStore"

class TokenStore(context: Context) {

    // STB-FX-07: opening the encrypted store must never crash startup;
    // a corrupted store is reset (one re-login) instead of crash-looping.
    private val prefs = createEncryptedPrefsWithRecovery(context, "ifoxy_tokens")

    fun saveAuth(auth: RuntimeAuth) {
        prefs.edit()
            .putString(KEY_ACCESS_TOKEN, auth.accessToken)
            .putString(KEY_REFRESH_TOKEN, auth.refreshToken)
            .putLong(KEY_EXPIRES_AT, auth.expiresAtEpochSeconds)
            .apply()
    }

    fun loadAuth(): RuntimeAuth? = runCatching {
        val access = prefs.getString(KEY_ACCESS_TOKEN, null)?.takeIf { it.isNotBlank() } ?: return@runCatching null
        val refresh = prefs.getString(KEY_REFRESH_TOKEN, null)?.takeIf { it.isNotBlank() }
        val expiresAt = prefs.getLong(KEY_EXPIRES_AT, 0L)
        RuntimeAuth(access, refresh, expiresAt)
    }.onFailure {
        AppLogger.w(TAG, "could not read the stored session", it)
    }.getOrNull()

    fun hasValidAccessToken(): Boolean {
        val auth = loadAuth() ?: return false
        if (auth.expiresAtEpochSeconds <= 0L) return false
        val nowSeconds = System.currentTimeMillis() / 1000
        return auth.expiresAtEpochSeconds - nowSeconds > CLOCK_SKEW_TOLERANCE_SECONDS
    }

    fun hasStoredSession(): Boolean = loadAuth() != null

    fun hasRefreshToken(): Boolean = loadAuth()?.refreshToken != null

    var pendingSessionToken: String?
        get() = prefs.getString(KEY_PENDING_SESSION_TOKEN, null)?.takeIf { it.isNotBlank() }
        set(value) {
            if (value != null) {
                prefs.edit().putString(KEY_PENDING_SESSION_TOKEN, value).apply()
            } else {
                prefs.edit().remove(KEY_PENDING_SESSION_TOKEN).apply()
            }
        }

    /** Email of the in-progress sign-in (multi-account vault bookkeeping);
     *  set at login start, consumed when the login completes. */
    var pendingLoginEmail: String?
        get() = prefs.getString(KEY_PENDING_LOGIN_EMAIL, null)?.takeIf { it.isNotBlank() }
        set(value) {
            if (value != null) {
                prefs.edit().putString(KEY_PENDING_LOGIN_EMAIL, value).apply()
            } else {
                prefs.edit().remove(KEY_PENDING_LOGIN_EMAIL).apply()
            }
        }

    fun clear() {
        prefs.edit().clear().apply()
    }

    companion object {
        private const val KEY_ACCESS_TOKEN = "access_token"
        private const val KEY_REFRESH_TOKEN = "refresh_token"
        private const val KEY_EXPIRES_AT = "expires_at"
        private const val KEY_PENDING_SESSION_TOKEN = "pending_session_token"
        private const val KEY_PENDING_LOGIN_EMAIL = "pending_login_email"

        private const val CLOCK_SKEW_TOLERANCE_SECONDS = 60L
    }
}
