package com.pishi.ifoxy.data

import android.content.SharedPreferences

/**
 * A [SharedPreferences] that never touches disk: values live only in a
 * guarded in-memory map for the life of the process.
 *
 * Used as the last-resort fallback of
 * [createEncryptedPrefsWithRecovery] when the encrypted store cannot
 * be opened even after a reset. The previous fallback wrote to a plain
 * on-disk store, which left tokens unencrypted at rest; this one
 * trades persistence for safety — the session must be re-entered after
 * restart, but nothing sensitive is ever written plaintext.
 *
 * `apply()` is synchronous here (there is no disk I/O to defer), and
 * `commit()` always returns true. Returned string sets are copies, per
 * the [SharedPreferences] contract.
 */
class InMemorySharedPreferences : SharedPreferences {

    private val lock = Any()
    private val values = HashMap<String, Any?>()
    private val listeners = HashSet<SharedPreferences.OnSharedPreferenceChangeListener>()

    override fun getAll(): Map<String, *> = synchronized(lock) { HashMap(values) }

    @Suppress("UNCHECKED_CAST")
    override fun getString(key: String, defValue: String?): String? = synchronized(lock) {
        (values[key] as? String) ?: defValue
    }

    @Suppress("UNCHECKED_CAST")
    override fun getStringSet(key: String, defValues: Set<String>?): Set<String>? =
        synchronized(lock) {
            (values[key] as? Set<String>)?.toHashSet() ?: defValues
        }

    override fun getInt(key: String, defValue: Int): Int = synchronized(lock) {
        (values[key] as? Int) ?: defValue
    }

    override fun getLong(key: String, defValue: Long): Long = synchronized(lock) {
        (values[key] as? Long) ?: defValue
    }

    override fun getFloat(key: String, defValue: Float): Float = synchronized(lock) {
        (values[key] as? Float) ?: defValue
    }

    override fun getBoolean(key: String, defValue: Boolean): Boolean = synchronized(lock) {
        (values[key] as? Boolean) ?: defValue
    }

    override fun contains(key: String): Boolean = synchronized(lock) { values.containsKey(key) }

    override fun edit(): SharedPreferences.Editor = InMemoryEditor()

    override fun registerOnSharedPreferenceChangeListener(
        listener: SharedPreferences.OnSharedPreferenceChangeListener,
    ) {
        synchronized(lock) { listeners.add(listener) }
    }

    override fun unregisterOnSharedPreferenceChangeListener(
        listener: SharedPreferences.OnSharedPreferenceChangeListener,
    ) {
        synchronized(lock) { listeners.remove(listener) }
    }

    private inner class InMemoryEditor : SharedPreferences.Editor {
        private val pending = HashMap<String, Any?>()
        private val removals = HashSet<String>()
        private var clearAll = false

        // Per the SharedPreferences contract, a null value removes the key.
        override fun putString(key: String, value: String?): SharedPreferences.Editor =
            apply {
                if (value == null) {
                    pending.remove(key)
                    removals.add(key)
                } else {
                    pending[key] = value
                }
            }

        override fun putStringSet(key: String, values: Set<String>?): SharedPreferences.Editor =
            apply {
                if (values == null) {
                    pending.remove(key)
                    removals.add(key)
                } else {
                    pending[key] = values.toHashSet()
                }
            }

        override fun putInt(key: String, value: Int): SharedPreferences.Editor =
            apply { pending[key] = value }

        override fun putLong(key: String, value: Long): SharedPreferences.Editor =
            apply { pending[key] = value }

        override fun putFloat(key: String, value: Float): SharedPreferences.Editor =
            apply { pending[key] = value }

        override fun putBoolean(key: String, value: Boolean): SharedPreferences.Editor =
            apply { pending[key] = value }

        override fun remove(key: String): SharedPreferences.Editor = apply {
            pending.remove(key)
            removals.add(key)
        }

        override fun clear(): SharedPreferences.Editor = apply {
            pending.clear()
            removals.clear()
            clearAll = true
        }

        override fun commit(): Boolean {
            val changedKeys: Set<String>
            val snapshot: Set<SharedPreferences.OnSharedPreferenceChangeListener>
            synchronized(lock) {
                if (clearAll) values.clear()
                removals.forEach { values.remove(it) }
                values.putAll(pending)
                changedKeys = (pending.keys + removals).toSet()
                snapshot = listeners.toSet()
            }
            changedKeys.forEach { key ->
                snapshot.forEach { it.onSharedPreferenceChanged(this@InMemorySharedPreferences, key) }
            }
            pending.clear()
            removals.clear()
            clearAll = false
            return true
        }

        override fun apply() {
            commit()
        }
    }
}
