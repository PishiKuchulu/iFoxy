package com.pishi.ifoxy.data

import android.content.Context
import com.pishi.ifoxy.data.model.Entitlement
import com.pishi.ifoxy.data.model.RuntimeAuth
import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.util.UUID

/**
 * One Firefox account known to the app. Token fields mirror [RuntimeAuth];
 * quota fields are the last known Guardian entitlement snapshot.
 */
@Serializable
data class StoredAccount(
    val id: String,
    val email: String,
    val accessToken: String,
    val refreshToken: String? = null,
    val expiresAtEpochSeconds: Long = 0,
    val quotaRemaining: Long? = null,
    val quotaMax: Long? = null,
    val isUnlimited: Boolean = false,
    val quotaCheckedAtEpochMs: Long = 0,
    val exhausted: Boolean = false,
) {
    fun toRuntimeAuth(): RuntimeAuth = RuntimeAuth(accessToken, refreshToken, expiresAtEpochSeconds)
}

/**
 * The account to rotate to when the active one is out of quota: the first
 * account in list order that is not the active one, is not marked
 * exhausted, and either is unlimited, has quota left, or has never been
 * measured. Pure and unit-tested.
 */
fun selectNextAccount(accounts: List<StoredAccount>, activeId: String?): StoredAccount? =
    accounts.firstOrNull { account ->
        account.id != activeId &&
            !account.exhausted &&
            (account.isUnlimited || account.quotaRemaining == null || account.quotaRemaining > 0)
    }

/**
 * Vault of all signed-in Firefox accounts (encrypted at rest, like
 * [TokenStore]). The [TokenStore] remains the single "active session"
 * working copy the rest of the app reads; this store holds every account
 * plus which one is active, and the two are kept in sync by harvesting
 * (TokenStore -> vault) and activation (vault -> TokenStore), orchestrated
 * by [AccountSwitcher].
 */
class AccountStore(context: Context) {

    private val prefs = createEncryptedPrefsWithRecovery(context, "ifoxy_accounts")
    private val json = Json { ignoreUnknownKeys = true }

    fun accounts(): List<StoredAccount> {
        val raw = prefs.getString(KEY_ACCOUNTS, null) ?: return emptyList()
        return runCatching { json.decodeFromString<List<StoredAccount>>(raw) }.getOrDefault(emptyList())
    }

    var activeAccountId: String?
        get() = prefs.getString(KEY_ACTIVE_ID, null)?.takeIf { it.isNotBlank() }
        set(value) {
            if (value == null) {
                prefs.edit().remove(KEY_ACTIVE_ID).apply()
            } else {
                prefs.edit().putString(KEY_ACTIVE_ID, value).apply()
            }
        }

    fun activeAccount(): StoredAccount? =
        accounts().firstOrNull { it.id == activeAccountId }

    fun save(account: StoredAccount) {
        val all = accounts().map { if (it.id == account.id) account else it }
        if (all.none { it.id == account.id }) return
        persist(all)
    }

    /** Add a freshly signed-in account (or refresh an existing one's
     *  tokens, matched by email) and make it the active account. */
    fun upsert(email: String, auth: RuntimeAuth): StoredAccount {
        val normalized = FxaAuthRepository.normalizeEmail(email)
        val all = accounts().toMutableList()
        val existing = all.firstOrNull { it.email.equals(normalized, ignoreCase = true) }
        val entry = if (existing != null) {
            existing.copy(
                accessToken = auth.accessToken,
                refreshToken = auth.refreshToken,
                expiresAtEpochSeconds = auth.expiresAtEpochSeconds,
            )
        } else {
            StoredAccount(
                id = UUID.randomUUID().toString(),
                email = normalized,
                accessToken = auth.accessToken,
                refreshToken = auth.refreshToken,
                expiresAtEpochSeconds = auth.expiresAtEpochSeconds,
            )
        }
        if (existing != null) {
            all[all.indexOf(existing)] = entry
        } else {
            all += entry
        }
        persist(all)
        activeAccountId = entry.id
        return entry
    }

    fun remove(id: String) {
        persist(accounts().filterNot { it.id == id })
        if (activeAccountId == id) activeAccountId = null
    }

    fun clear() {
        prefs.edit().clear().apply()
    }

    /** Copy the live session tokens from [tokenStore] into the active
     *  account's vault entry (refresh may have rotated them). */
    fun harvestFrom(tokenStore: TokenStore) {
        val active = activeAccount() ?: return
        val auth = tokenStore.loadAuth() ?: return
        if (auth.accessToken != active.accessToken ||
            auth.refreshToken != active.refreshToken ||
            auth.expiresAtEpochSeconds != active.expiresAtEpochSeconds
        ) {
            save(
                active.copy(
                    accessToken = auth.accessToken,
                    refreshToken = auth.refreshToken,
                    expiresAtEpochSeconds = auth.expiresAtEpochSeconds,
                ),
            )
        }
    }

    /** Record the quota reported by a freshly minted proxy pass. */
    fun recordPassQuota(remaining: Long?, max: Long?) {
        val active = activeAccount() ?: return
        save(
            active.copy(
                quotaRemaining = remaining ?: active.quotaRemaining,
                quotaMax = max ?: active.quotaMax,
                quotaCheckedAtEpochMs = System.currentTimeMillis(),
                exhausted = if (remaining != null) remaining <= 0 else active.exhausted,
            ),
        )
    }

    /** Record a Guardian entitlement snapshot for the active account. */
    fun recordEntitlement(entitlement: Entitlement) {
        val active = activeAccount() ?: return
        val remaining = entitlement.quotaRemaining ?: active.quotaRemaining
        save(
            active.copy(
                quotaRemaining = remaining,
                quotaMax = entitlement.maxBytes ?: active.quotaMax,
                isUnlimited = !entitlement.limitedBandwidth,
                quotaCheckedAtEpochMs = System.currentTimeMillis(),
                exhausted = entitlement.limitedBandwidth && remaining != null && remaining <= 0,
            ),
        )
    }

    private fun persist(all: List<StoredAccount>) {
        prefs.edit().putString(KEY_ACCOUNTS, json.encodeToString(all)).apply()
    }

    companion object {
        private const val KEY_ACCOUNTS = "accounts_json"
        private const val KEY_ACTIVE_ID = "active_id"
    }
}
