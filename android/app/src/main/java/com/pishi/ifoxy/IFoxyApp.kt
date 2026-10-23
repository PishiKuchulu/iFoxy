package com.pishi.ifoxy

import android.app.Application
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.res.Configuration
import android.os.Build
import android.util.Log
import com.pishi.ifoxy.data.ACCOUNT_ALERTS_CHANNEL_ID
import com.pishi.ifoxy.data.AccountStore
import com.pishi.ifoxy.data.AccountSwitcher
import com.pishi.ifoxy.data.ControlPlaneHttp
import com.pishi.ifoxy.data.CrashReporter
import com.pishi.ifoxy.data.FxaAuthRepository
import com.pishi.ifoxy.data.GuardianClient
import com.pishi.ifoxy.data.ProxyStateStore
import com.pishi.ifoxy.data.ServerListClient
import com.pishi.ifoxy.data.SettingsStore
import com.pishi.ifoxy.data.TokenStore
import com.pishi.ifoxy.vpn.IFoxyVpnService
import com.pishi.ifoxy.vpn.upstream.NettyLoggingBridge
import com.pishi.ifoxy.vpn.upstream.UpstreamTrust
import com.pishi.ifoxy.widget.QuickConnectWidgetProvider
import org.conscrypt.Conscrypt
import java.security.Security

class IFoxyApp : Application() {

    lateinit var tokenStore: TokenStore
    lateinit var proxyStateStore: ProxyStateStore
    lateinit var settingsStore: SettingsStore
    lateinit var guardianClient: GuardianClient
    lateinit var serverListClient: ServerListClient
    lateinit var authRepository: FxaAuthRepository
    lateinit var accountStore: AccountStore
    lateinit var accountSwitcher: AccountSwitcher

    override fun onCreate() {
        super.onCreate()

        CrashReporter.install(this)
        CrashReporter.replayLastCrashIfAny(this)

        NettyLoggingBridge.install()
        installConscrypt()
        UpstreamTrust.init(this)
        tokenStore = TokenStore(this)
        proxyStateStore = ProxyStateStore(this)
        settingsStore = SettingsStore(this)
        ControlPlaneHttp.tlsSplitModeProvider = { settingsStore.tlsSplitMode }
        guardianClient = GuardianClient()
        serverListClient = ServerListClient(this)
        accountStore = AccountStore(this)
        accountSwitcher = AccountSwitcher(this, accountStore, tokenStore, settingsStore)
        authRepository = FxaAuthRepository(tokenStore, accountStore = accountStore)
        createNotificationChannel()
    }

    private fun installConscrypt() {
        runCatching {
            Security.insertProviderAt(Conscrypt.newProvider(), 1)
        }.onFailure {
            Log.w("IFoxyApp", "failed to install Conscrypt security provider", it)
        }
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val manager = getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(
            NotificationChannel(
                VPN_NOTIFICATION_CHANNEL_ID,
                "VPN status",
                NotificationManager.IMPORTANCE_LOW,
            ),
        )
        manager.createNotificationChannel(
            NotificationChannel(
                ACCOUNT_ALERTS_CHANNEL_ID,
                "Account alerts",
                NotificationManager.IMPORTANCE_DEFAULT,
            ),
        )
    }

    override fun onConfigurationChanged(newConfig: Configuration) {
        super.onConfigurationChanged(newConfig)
        QuickConnectWidgetProvider.updateAll(this, IFoxyVpnService.state.value)
    }

    companion object {
        const val VPN_NOTIFICATION_CHANNEL_ID = "ifoxy_status"
    }
}
