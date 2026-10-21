package com.pishi.ifoxy.quicksettings

import android.app.PendingIntent
import android.content.Intent
import android.graphics.drawable.Icon
import android.net.VpnService
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import com.pishi.ifoxy.IFoxyApp
import com.pishi.ifoxy.MainActivity
import com.pishi.ifoxy.R
import com.pishi.ifoxy.data.model.ConnectionState
import com.pishi.ifoxy.data.SettingsStore
import com.pishi.ifoxy.data.TokenStore
import com.pishi.ifoxy.vpn.IFoxyVpnService
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch

class QuickConnectTileService : TileService() {

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    private var listenJob: Job? = null

    override fun onStartListening() {
        super.onStartListening()
        listenJob?.cancel()
        listenJob = serviceScope.launch {
            IFoxyVpnService.state.collect { state ->
                updateTileState(state)
            }
        }
    }

    override fun onStopListening() {
        listenJob?.cancel()
        listenJob = null
        super.onStopListening()
    }

    override fun onClick() {
        super.onClick()
        when (IFoxyVpnService.state.value) {
            ConnectionState.CONNECTED, ConnectionState.CONNECTING -> {
                IFoxyVpnService.stop(this)
            }
            ConnectionState.DISCONNECTED -> {
                val app = applicationContext as? IFoxyApp
                val tokenStore = app?.tokenStore ?: TokenStore(this)
                if (!tokenStore.hasStoredSession()) {
                    launchMainActivityAndCollapse()
                    return
                }

                val settingsStore = app?.settingsStore ?: SettingsStore(this)
                if (settingsStore.proxyOnlyMode) {
                    IFoxyVpnService.start(this)
                    return
                }

                val prepareIntent = VpnService.prepare(this)
                if (prepareIntent != null) {
                    launchMainActivityAndCollapse()
                } else {
                    IFoxyVpnService.start(this)
                }
            }
        }
    }

    private fun updateTileState(state: ConnectionState) {
        val tile = qsTile ?: return
        tile.icon = Icon.createWithResource(this, android.R.drawable.ic_lock_lock)
        tile.label = getString(R.string.quick_connect)
        when (state) {
            ConnectionState.CONNECTED -> {
                tile.state = Tile.STATE_ACTIVE
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    tile.subtitle = getString(R.string.quick_connect_connected)
                }
            }
            ConnectionState.CONNECTING -> {
                tile.state = Tile.STATE_ACTIVE
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    tile.subtitle = getString(R.string.quick_connect_connecting)
                }
            }
            ConnectionState.DISCONNECTED -> {
                tile.state = Tile.STATE_INACTIVE
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    tile.subtitle = getString(R.string.quick_connect_disconnected)
                }
            }
        }
        tile.updateTile()
    }

    private fun launchMainActivityAndCollapse() {
        val intent = Intent(this, MainActivity::class.java).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP)
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            val pendingIntent = PendingIntent.getActivity(
                this,
                0,
                intent,
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
            )
            startActivityAndCollapse(pendingIntent)
        } else {
            @Suppress("DEPRECATION")
            startActivityAndCollapse(intent)
        }
    }

    override fun onDestroy() {
        listenJob?.cancel()
        serviceScope.cancel()
        super.onDestroy()
    }
}
