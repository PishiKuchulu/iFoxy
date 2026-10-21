package com.pishi.ifoxy.data

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

private const val TAG = "EncryptedPrefs"

/**
 * STB-FX-07: EncryptedSharedPreferences can fail permanently when the
 * keystore entry or the stored ciphertext is corrupted (a known failure mode
 * of security-crypto), and the old code let that exception escape from
 * Application.onCreate — an unrecoverable crash loop on every launch.
 *
 * Recovery strategy: try to open the encrypted store; on failure, delete the
 * corrupted store and retry once (the user simply signs in again / re-enters
 * the value). If it still fails, fall back to a plain store for that name so
 * the app keeps working, and say so loudly in the log.
 */
fun createEncryptedPrefsWithRecovery(context: Context, name: String): SharedPreferences {
    val appContext = context.applicationContext
    fun build(): SharedPreferences {
        val masterKey = MasterKey.Builder(appContext)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()
        return EncryptedSharedPreferences.create(
            appContext,
            name,
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
        )
    }

    try {
        return build()
    } catch (first: Exception) {
        AppLogger.w(TAG, "encrypted store '$name' could not be opened; resetting it", first)
    }
    runCatching { appContext.deleteSharedPreferences(name) }
    try {
        return build()
    } catch (second: Exception) {
        AppLogger.e(TAG, "encrypted store '$name' still unavailable after reset; using a plain fallback store", second)
        return appContext.getSharedPreferences("${name}_plain_fallback", Context.MODE_PRIVATE)
    }
}
