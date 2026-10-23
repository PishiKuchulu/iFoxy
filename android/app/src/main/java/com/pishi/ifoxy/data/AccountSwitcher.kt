package com.pishi.ifoxy.data

import android.app.Notification
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import com.pishi.ifoxy.MainActivity
import com.pishi.ifoxy.R
import com.pishi.ifoxy.data.model.ConnectionState
import com.pishi.ifoxy.vpn.IFoxyVpnService
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.withTimeoutOrNull

private const val TAG = "AccountSwitcher"

const val ACCOUNT_ALERTS_CHANNEL_ID = "ifoxy_account_alerts"

sealed interface RotationResult {
    data class Rotated(val fromEmail: String, val toEmail: String) : RotationResult
    data class NoNextAccount(val exhaustedEmail: String) : RotationResult
    data object NoAccounts : RotationResult
}

/**
 * Orchestrates multi-account operations across [AccountStore] (the vault),
 * [TokenStore] (the live session the rest of the app reads) and
 * [SettingsStore] (the quota snapshot the UI shows). Safe to construct
 * ad-hoc with the caller's own store instances — all stores read/write the
 * same underlying encrypted files.
 */
class AccountSwitcher(
    private val appContext: Context,
    private val accountStore: AccountStore,
    private val tokenStore: TokenStore,
    private val settingsStore: SettingsStore,
) {

    /** Persist any refreshed tokens of the outgoing account to the vault. */
    fun harvestActive() {
        accountStore.harvestFrom(tokenStore)
    }

    /**
     * Make [accountId] the live account: its tokens become the TokenStore
     * session and the UI quota cache is swapped to its snapshot.
     */
    fun activate(accountId: String): Boolean {
        harvestActive()
        val target = accountStore.accounts().firstOrNull { it.id == accountId } ?: return false
        accountStore.activeAccountId = target.id
        tokenStore.saveAuth(target.toRuntimeAuth())
        settingsStore.cachedQuotaRemaining = target.quotaRemaining
        settingsStore.cachedQuotaMax = target.quotaMax
        settingsStore.cachedIsUnlimited = target.isUnlimited
        AppLogger.i(TAG, "active account is now ${target.email}")
        return true
    }

    /**
     * The active account's quota is gone: mark it exhausted and activate
     * the next viable account, if any. Callers that mint proxy passes can
     * simply retry afterwards — the session now belongs to the new account.
     */
    fun rotateOnQuotaExhausted(): RotationResult {
        harvestActive()
        val active = accountStore.activeAccount() ?: return RotationResult.NoAccounts
        accountStore.save(
            active.copy(
                quotaRemaining = 0,
                exhausted = true,
                quotaCheckedAtEpochMs = System.currentTimeMillis(),
            ),
        )
        val next = selectNextAccount(accountStore.accounts(), active.id)
            ?: return RotationResult.NoNextAccount(active.email)
        activate(next.id)
        AppLogger.i(TAG, "quota exhausted on ${active.email}; switched to ${next.email}")
        notifyAccountAlert(
            title = "Account switched",
            text = "Quota finished on ${active.email} — iFoxy switched to ${next.email}.",
        )
        return RotationResult.Rotated(active.email, next.email)
    }

    /** Restart the tunnel (after a manual account switch) so the new
     *  account takes effect immediately instead of at the next pass
     *  renewal. No-op while disconnected. */
    suspend fun restartTunnelIfRunning() {
        if (IFoxyVpnService.state.value == ConnectionState.DISCONNECTED) return
        AppLogger.i(TAG, "restarting the tunnel so the account switch takes effect")
        IFoxyVpnService.stop(appContext)
        withTimeoutOrNull(6_000) {
            IFoxyVpnService.state.first { it == ConnectionState.DISCONNECTED }
        }
        IFoxyVpnService.start(appContext)
    }

    fun notifyAccountAlert(title: String, text: String) {
        runCatching {
            val manager = appContext.getSystemService(NotificationManager::class.java) ?: return
            val openApp = PendingIntent.getActivity(
                appContext,
                0,
                Intent(appContext, MainActivity::class.java),
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
            )
            val notification = Notification.Builder(appContext, ACCOUNT_ALERTS_CHANNEL_ID)
                .setSmallIcon(R.mipmap.ic_launcher)
                .setContentTitle(title)
                .setContentText(text)
                .setStyle(Notification.BigTextStyle().bigText(text))
                .setContentIntent(openApp)
                .setAutoCancel(true)
                .build()
            manager.notify(NOTIFICATION_ID_ACCOUNT_ALERT, notification)
        }.onFailure {
            AppLogger.w(TAG, "could not post the account alert notification", it)
        }
    }

    companion object {
        private const val NOTIFICATION_ID_ACCOUNT_ALERT = 4202
    }
}
