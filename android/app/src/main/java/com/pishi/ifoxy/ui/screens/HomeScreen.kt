package com.pishi.ifoxy.ui.screens

import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.EaseInOut
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.KeyboardArrowRight
import androidx.compose.material.icons.filled.ArrowDownward
import androidx.compose.material.icons.filled.Block
import androidx.compose.material.icons.filled.BrightnessAuto
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.DarkMode
import androidx.compose.material.icons.filled.LightMode
import androidx.compose.material.icons.filled.LocationOn
import androidx.compose.material.icons.filled.PowerSettingsNew
import androidx.compose.material.icons.filled.Public
import androidx.compose.material.icons.filled.SignalCellularAlt
import androidx.compose.material.icons.filled.Tune
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.scale
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.pishi.ifoxy.IFoxyApp
import com.pishi.ifoxy.data.GUARDIAN_ENDPOINT_DEFAULT
import com.pishi.ifoxy.data.RECOMMENDED_COUNTRY_CODE
import com.pishi.ifoxy.data.ServerListClient
import com.pishi.ifoxy.data.formatBytes
import com.pishi.ifoxy.data.model.ConnectionState
import com.pishi.ifoxy.data.model.VpnCountry
import com.pishi.ifoxy.data.model.emojiFlag
import com.pishi.ifoxy.ui.components.WorldMapLayer
import com.pishi.ifoxy.ui.theme.IFoxyBgDark
import com.pishi.ifoxy.ui.theme.IFoxyCardDark
import com.pishi.ifoxy.ui.theme.IFoxyErrorOnDark
import com.pishi.ifoxy.ui.theme.IFoxyErrorOnYellow
import com.pishi.ifoxy.ui.theme.IFoxyGreen
import com.pishi.ifoxy.ui.theme.IFoxyInk
import com.pishi.ifoxy.ui.theme.IFoxyMapOnYellow
import com.pishi.ifoxy.ui.theme.IFoxyNeonOrange
import com.pishi.ifoxy.ui.theme.IFoxyYellow
import com.pishi.ifoxy.ui.theme.PoppinsFamily
import com.pishi.ifoxy.ui.theme.ThemeController
import com.pishi.ifoxy.ui.theme.ThemeMode
import com.pishi.ifoxy.vpn.ExitCheck
import com.pishi.ifoxy.vpn.IFoxyVpnService
import com.pishi.ifoxy.vpn.IpLocationInfo
import com.pishi.ifoxy.vpn.PingUtil
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.Locale

/**
 * iFoxy home, per the Penpot "iFoxy — Screens" design (01 Connected /
 * 02 Disconnected): brand-yellow screen with a neon halo while connected,
 * ink-dark screen while disconnected, drifting world map in both states
 * (Motion & Glow spec: 90 s connected / 120 s disconnected). All data is
 * the app's real state — selected/last-used server, recommended server,
 * session bytes, ping, exit IP and the Guardian quota.
 */
@OptIn(ExperimentalFoundationApi::class)
@Composable
fun HomeScreen(
    app: IFoxyApp,
    themeController: ThemeController,
    onRequestConnect: () -> Unit,
    onDisconnect: () -> Unit,
    onOpenServers: () -> Unit,
    onOpenSettings: () -> Unit,
) {
    val state by IFoxyVpnService.state.collectAsState()
    val lastError by IFoxyVpnService.lastError.collectAsState()
    val liveStats by IFoxyVpnService.vpnLiveStats.collectAsState()
    val connectedAtEpochMs by IFoxyVpnService.connectedAtEpochMs.collectAsState()
    val pingLatency by IFoxyVpnService.pingLatencyMs.collectAsState()
    val vpnEdgeIp by IFoxyVpnService.vpnEdgeIp.collectAsState()

    val selectedProxy by app.proxyStateStore.selectedProxyFlow.collectAsState()

    val connected = state == ConnectionState.CONNECTED
    val connecting = state == ConnectionState.CONNECTING
    val onYellow = connected

    val background by animateColorAsState(
        targetValue = if (onYellow) IFoxyYellow else IFoxyBgDark,
        label = "home-background",
    )
    val ink = if (onYellow) IFoxyInk else Color.White
    val muted = if (onYellow) IFoxyInk.copy(alpha = 0.62f) else Color.White.copy(alpha = 0.55f)
    val cardBg = if (onYellow) Color.White else IFoxyCardDark
    val cardBgAlt = if (onYellow) Color.White.copy(alpha = 0.45f) else IFoxyCardDark
    val chipBg = if (onYellow) IFoxyInk else IFoxyCardDark
    val errorColor = if (onYellow) IFoxyErrorOnYellow else IFoxyErrorOnDark

    val systemInDarkTheme = isSystemInDarkTheme()
    val haptics = LocalHapticFeedback.current
    val scope = rememberCoroutineScope()

    var elapsedSeconds by remember { mutableLongStateOf(0L) }
    var realIp by remember {
        mutableStateOf<IpLocationInfo?>(
            app.settingsStore.cachedRealIp?.let {
                IpLocationInfo(it, app.settingsStore.cachedRealCountry.orEmpty())
            },
        )
    }
    var isPinging by remember { mutableStateOf(false) }
    var disconnectedPingLatency by remember { mutableStateOf<Int?>(null) }
    var quotaRemaining by remember { mutableStateOf(app.settingsStore.cachedQuotaRemaining) }
    var quotaMax by remember { mutableStateOf(app.settingsStore.cachedQuotaMax) }
    var isUnlimited by remember { mutableStateOf(app.settingsStore.cachedIsUnlimited) }
    var recommendedCountry by remember { mutableStateOf<VpnCountry?>(null) }

    LaunchedEffect(state) {
        if (state == ConnectionState.CONNECTED) {
            quotaRemaining = app.settingsStore.cachedQuotaRemaining
            quotaMax = app.settingsStore.cachedQuotaMax
            isUnlimited = app.settingsStore.cachedIsUnlimited
        }
    }

    LaunchedEffect(state, connectedAtEpochMs) {
        if (state == ConnectionState.CONNECTED && connectedAtEpochMs != null) {
            while (isActive) {
                val now = System.currentTimeMillis()
                elapsedSeconds = ((now - connectedAtEpochMs!!) / 1000L).coerceAtLeast(0L)
                delay(1000L)
            }
        } else {
            elapsedSeconds = 0L
        }
    }

    LaunchedEffect(Unit) {
        launch {
            ExitCheck().fetchDirectIpInfo().onSuccess { info ->
                realIp = info
                app.settingsStore.cachedRealIp = info.ip
                app.settingsStore.cachedRealCountry = info.countryCode
            }
        }
        launch {
            val cached = withContext(Dispatchers.IO) { app.serverListClient.loadCachedCountries() }
            recommendedCountry = cached.firstOrNull { it.code == RECOMMENDED_COUNTRY_CODE }
        }
        launch {
            val token = app.authRepository.currentAccessToken()
            if (token != null) {
                runCatching { app.guardianClient.fetchUserInfo(GUARDIAN_ENDPOINT_DEFAULT, token) }
                    .onSuccess { entitlement ->
                        val unlimited = !entitlement.limitedBandwidth
                        isUnlimited = unlimited
                        app.settingsStore.cachedIsUnlimited = unlimited
                        entitlement.quotaRemaining?.let {
                            quotaRemaining = it
                            app.settingsStore.cachedQuotaRemaining = it
                        }
                        entitlement.maxBytes?.let {
                            quotaMax = it
                            app.settingsStore.cachedQuotaMax = it
                        }
                    }
            }
        }
    }

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(background),
    ) {
        // Drifting world map behind the hero (Motion & Glow spec).
        WorldMapLayer(
            color = if (onYellow) IFoxyMapOnYellow.copy(alpha = 0.5f) else Color.White.copy(alpha = 0.05f),
            driftMillis = if (connected) 90_000 else 120_000,
            modifier = Modifier
                .fillMaxWidth()
                .align(Alignment.Center),
        )

        Column(
            modifier = Modifier
                .fillMaxSize()
                .statusBarsPadding()
                .verticalScroll(rememberScrollState()),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Column(
                modifier = Modifier
                    .widthIn(max = 520.dp)
                    .fillMaxWidth()
                    .padding(horizontal = 24.dp),
            ) {
                // Header: wordmark + theme / settings round buttons.
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(top = 14.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Row(verticalAlignment = Alignment.Top) {
                        Text(
                            "iFoxy",
                            style = TextStyle(
                                fontFamily = PoppinsFamily,
                                fontWeight = FontWeight.Bold,
                                fontSize = 22.sp,
                            ),
                            color = ink,
                        )
                        Box(
                            modifier = Modifier
                                .padding(start = 4.dp, top = 4.dp)
                                .size(7.dp)
                                .clip(CircleShape)
                                .background(IFoxyNeonOrange),
                        )
                    }
                    Spacer(Modifier.weight(1f))
                    val mode = themeController.mode
                    val showingDark = themeController.resolveDark(systemInDarkTheme)
                    Box(
                        modifier = Modifier
                            .size(42.dp)
                            .clip(CircleShape)
                            .background(chipBg)
                            .combinedClickable(
                                role = Role.Button,
                                onClick = { themeController.toggle(systemInDarkTheme) },
                                onLongClick = {
                                    haptics.performHapticFeedback(HapticFeedbackType.LongPress)
                                    themeController.set(ThemeMode.SYSTEM)
                                },
                            ),
                        contentAlignment = Alignment.Center,
                    ) {
                        Icon(
                            imageVector = when (mode) {
                                ThemeMode.SYSTEM -> Icons.Filled.BrightnessAuto
                                ThemeMode.LIGHT -> Icons.Filled.LightMode
                                ThemeMode.DARK -> Icons.Filled.DarkMode
                            },
                            contentDescription = when (mode) {
                                ThemeMode.SYSTEM ->
                                    "Theme: follow system. Tap to switch to ${if (showingDark) "light" else "dark"} mode"
                                ThemeMode.LIGHT -> "Theme: light. Tap for dark mode, long press to follow the system"
                                ThemeMode.DARK -> "Theme: dark. Tap for light mode, long press to follow the system"
                            },
                            tint = if (onYellow) IFoxyYellow else Color.White,
                            modifier = Modifier.size(20.dp),
                        )
                    }
                    Spacer(Modifier.width(10.dp))
                    Box(
                        modifier = Modifier
                            .size(42.dp)
                            .clip(CircleShape)
                            .background(chipBg)
                            .clickable(role = Role.Button, onClick = onOpenSettings),
                        contentAlignment = Alignment.Center,
                    ) {
                        Icon(
                            imageVector = Icons.Filled.Tune,
                            contentDescription = "Settings",
                            tint = if (onYellow) IFoxyYellow else Color.White,
                            modifier = Modifier.size(20.dp),
                        )
                    }
                }

                Spacer(Modifier.height(22.dp))
                Text(
                    "Recent Connection",
                    style = TextStyle(
                        fontFamily = PoppinsFamily,
                        fontWeight = FontWeight.Medium,
                        fontSize = 13.sp,
                    ),
                    color = muted,
                )
                Spacer(Modifier.height(10.dp))

                // Recent / recommended cards.
                Row(modifier = Modifier.fillMaxWidth()) {
                    // Last used (current selection).
                    Box(
                        modifier = Modifier
                            .weight(1f)
                            .height(96.dp)
                            .clip(RoundedCornerShape(20.dp))
                            .background(cardBg)
                            .clickable(role = Role.Button) {
                                if (!connected && !connecting && selectedProxy != null) {
                                    onRequestConnect()
                                } else {
                                    onOpenServers()
                                }
                            }
                            .padding(14.dp),
                    ) {
                        Column {
                            val flag = selectedProxy?.emojiFlag
                            if (!flag.isNullOrBlank()) {
                                Text(flag, fontSize = 20.sp)
                            } else {
                                Icon(
                                    imageVector = Icons.Filled.Public,
                                    contentDescription = null,
                                    tint = ink,
                                    modifier = Modifier.size(20.dp),
                                )
                            }
                            Spacer(Modifier.height(6.dp))
                            Text(
                                selectedProxy?.let { it.countryName.ifBlank { it.countryCode } } ?: "No location",
                                style = TextStyle(
                                    fontFamily = PoppinsFamily,
                                    fontWeight = FontWeight.SemiBold,
                                    fontSize = 14.sp,
                                ),
                                color = ink,
                                maxLines = 1,
                            )
                            Spacer(Modifier.height(2.dp))
                            when {
                                connected -> Row(verticalAlignment = Alignment.CenterVertically) {
                                    Icon(
                                        imageVector = Icons.Filled.CheckCircle,
                                        contentDescription = null,
                                        tint = IFoxyGreen,
                                        modifier = Modifier.size(13.dp),
                                    )
                                    Spacer(Modifier.width(4.dp))
                                    Text(
                                        "Connected",
                                        style = TextStyle(
                                            fontFamily = PoppinsFamily,
                                            fontWeight = FontWeight.Medium,
                                            fontSize = 12.sp,
                                        ),
                                        color = IFoxyGreen,
                                    )
                                }
                                connecting -> Text(
                                    "Connecting\u2026",
                                    style = TextStyle(
                                        fontFamily = PoppinsFamily,
                                        fontWeight = FontWeight.Medium,
                                        fontSize = 12.sp,
                                    ),
                                    color = muted,
                                )
                                else -> Text(
                                    if (selectedProxy != null) "Last used" else "Choose a location",
                                    style = TextStyle(
                                        fontFamily = PoppinsFamily,
                                        fontWeight = FontWeight.Medium,
                                        fontSize = 12.sp,
                                    ),
                                    color = muted,
                                )
                            }
                        }
                    }

                    Spacer(Modifier.width(12.dp))

                    // Recommended quick-connect.
                    Box(
                        modifier = Modifier
                            .weight(1f)
                            .height(96.dp)
                            .clip(RoundedCornerShape(20.dp))
                            .background(cardBgAlt)
                            .clickable(role = Role.Button, enabled = !connecting) {
                                if (connected) {
                                    onOpenServers()
                                } else {
                                    val country = recommendedCountry
                                    val chosen = country?.let {
                                        ServerListClient.candidatesForCountry(
                                            listOf(it),
                                            it.code,
                                        ).randomOrNull()
                                    }
                                    if (chosen != null) {
                                        app.proxyStateStore.save(chosen)
                                        onRequestConnect()
                                    } else {
                                        onOpenServers()
                                    }
                                }
                            }
                            .padding(14.dp),
                    ) {
                        Column {
                            val recFlag = recommendedCountry?.emojiFlag
                            if (!recFlag.isNullOrBlank()) {
                                Text(recFlag, fontSize = 20.sp)
                            } else {
                                Icon(
                                    imageVector = Icons.Filled.Block,
                                    contentDescription = null,
                                    tint = ink,
                                    modifier = Modifier.size(20.dp),
                                )
                            }
                            Spacer(Modifier.height(6.dp))
                            Text(
                                recommendedCountry?.name ?: "Recommended",
                                style = TextStyle(
                                    fontFamily = PoppinsFamily,
                                    fontWeight = FontWeight.SemiBold,
                                    fontSize = 14.sp,
                                ),
                                color = ink,
                                maxLines = 1,
                            )
                            Spacer(Modifier.height(2.dp))
                            Text(
                                if (connected) "Switch" else "Connect",
                                style = TextStyle(
                                    fontFamily = PoppinsFamily,
                                    fontWeight = FontWeight.Medium,
                                    fontSize = 12.sp,
                                ),
                                color = if (onYellow) muted else IFoxyYellow,
                            )
                        }
                    }
                }

                // Power hero with neon halo (connected) / static ring.
                Spacer(Modifier.height(30.dp))
                Box(
                    modifier = Modifier.fillMaxWidth(),
                    contentAlignment = Alignment.Center,
                ) {
                    if (connected) {
                        val haloTransition = rememberInfiniteTransition(label = "power-halo")
                        val haloAlpha by haloTransition.animateFloat(
                            initialValue = 0.35f,
                            targetValue = 0.60f,
                            animationSpec = infiniteRepeatable(
                                animation = tween(durationMillis = 2400, easing = EaseInOut),
                                repeatMode = RepeatMode.Reverse,
                            ),
                            label = "power-halo-alpha",
                        )
                        val haloScale by haloTransition.animateFloat(
                            initialValue = 1f,
                            targetValue = 1.06f,
                            animationSpec = infiniteRepeatable(
                                animation = tween(durationMillis = 2400, easing = EaseInOut),
                                repeatMode = RepeatMode.Reverse,
                            ),
                            label = "power-halo-scale",
                        )
                        Box(
                            modifier = Modifier
                                .size(210.dp)
                                .scale(haloScale)
                                .clip(CircleShape)
                                .background(
                                    Brush.radialGradient(
                                        colors = listOf(
                                            IFoxyNeonOrange.copy(alpha = haloAlpha),
                                            IFoxyNeonOrange.copy(alpha = 0f),
                                        ),
                                    ),
                                ),
                        )
                        Box(
                            modifier = Modifier
                                .size(178.dp)
                                .border(2.dp, IFoxyNeonOrange.copy(alpha = 0.45f), CircleShape),
                        )
                    } else {
                        Box(
                            modifier = Modifier
                                .size(178.dp)
                                .border(
                                    1.5.dp,
                                    (if (onYellow) IFoxyInk else Color.White).copy(alpha = 0.22f),
                                    CircleShape,
                                ),
                        )
                    }
                    Box(
                        modifier = Modifier
                            .size(128.dp)
                            .clip(CircleShape)
                            .background(if (connected) IFoxyInk else IFoxyCardDark)
                            .clickable(role = Role.Button) {
                                if (state == ConnectionState.DISCONNECTED) onRequestConnect() else onDisconnect()
                            },
                        contentAlignment = Alignment.Center,
                    ) {
                        Icon(
                            imageVector = Icons.Filled.PowerSettingsNew,
                            contentDescription = if (state == ConnectionState.DISCONNECTED) "Connect" else "Disconnect",
                            tint = Color.White.copy(alpha = if (connected) 1f else 0.75f),
                            modifier = Modifier.size(54.dp),
                        )
                    }
                }

                Spacer(Modifier.height(22.dp))
                Text(
                    text = if (connected) formatDuration(elapsedSeconds) else "00:00:00",
                    style = TextStyle(
                        fontFamily = PoppinsFamily,
                        fontWeight = FontWeight.Bold,
                        fontSize = 34.sp,
                        fontFeatureSettings = "tnum",
                    ),
                    color = if (connected || connecting) ink else muted,
                    modifier = Modifier.align(Alignment.CenterHorizontally),
                )
                Spacer(Modifier.height(6.dp))
                Row(
                    modifier = Modifier.align(Alignment.CenterHorizontally),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    when {
                        connected -> {
                            Icon(
                                imageVector = Icons.Filled.LocationOn,
                                contentDescription = null,
                                tint = ink,
                                modifier = Modifier.size(15.dp),
                            )
                            Spacer(Modifier.width(4.dp))
                            val countryLabel = selectedProxy?.countryName?.ifBlank { null }
                                ?: vpnEdgeIp?.countryCode?.takeIf { it.isNotEmpty() }
                                    ?.let { Locale("", it).displayCountry }
                            Text(
                                listOfNotNull(vpnEdgeIp?.ip, countryLabel).joinToString(" \u00B7 ")
                                    .ifBlank { "Checking\u2026" },
                                style = TextStyle(
                                    fontFamily = PoppinsFamily,
                                    fontWeight = FontWeight.Medium,
                                    fontSize = 13.5.sp,
                                ),
                                color = ink,
                            )
                        }
                        connecting -> Text(
                            "Establishing secure tunnel\u2026",
                            style = TextStyle(
                                fontFamily = PoppinsFamily,
                                fontWeight = FontWeight.Medium,
                                fontSize = 13.5.sp,
                            ),
                            color = muted,
                        )
                        else -> Text(
                            "Not connected",
                            style = TextStyle(
                                fontFamily = PoppinsFamily,
                                fontWeight = FontWeight.Medium,
                                fontSize = 13.5.sp,
                            ),
                            color = muted,
                        )
                    }
                }

                val error = lastError
                if (error != null && !connecting) {
                    Spacer(Modifier.height(8.dp))
                    Text(
                        text = error,
                        textAlign = TextAlign.Center,
                        style = TextStyle(
                            fontFamily = PoppinsFamily,
                            fontWeight = FontWeight.Medium,
                            fontSize = 12.5.sp,
                        ),
                        color = errorColor,
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 8.dp),
                    )
                }

                // Stats: session data + ping (tap ping to re-measure).
                Spacer(Modifier.height(26.dp))
                Row(modifier = Modifier.fillMaxWidth()) {
                    Column(
                        modifier = Modifier.weight(1f),
                        horizontalAlignment = Alignment.CenterHorizontally,
                    ) {
                        Box(
                            modifier = Modifier
                                .size(38.dp)
                                .clip(CircleShape)
                                .background(chipBg),
                            contentAlignment = Alignment.Center,
                        ) {
                            Icon(
                                imageVector = Icons.Filled.ArrowDownward,
                                contentDescription = null,
                                tint = if (onYellow) Color.White else Color.White.copy(alpha = 0.85f),
                                modifier = Modifier.size(17.dp),
                            )
                        }
                        Spacer(Modifier.height(8.dp))
                        Text(
                            "Session data",
                            style = TextStyle(
                                fontFamily = PoppinsFamily,
                                fontWeight = FontWeight.Normal,
                                fontSize = 12.sp,
                            ),
                            color = muted,
                        )
                        Spacer(Modifier.height(2.dp))
                        Text(
                            if (connected) formatBytes(liveStats.sessionBytes) else "\u2014",
                            style = TextStyle(
                                fontFamily = PoppinsFamily,
                                fontWeight = FontWeight.SemiBold,
                                fontSize = 16.sp,
                            ),
                            color = ink,
                        )
                    }
                    Column(
                        modifier = Modifier
                            .weight(1f)
                            .clip(RoundedCornerShape(12.dp))
                            .clickable(role = Role.Button) {
                                if (!isPinging) {
                                    scope.launch {
                                        isPinging = true
                                        haptics.performHapticFeedback(HapticFeedbackType.LongPress)
                                        if (state == ConnectionState.CONNECTED) {
                                            IFoxyVpnService.pingNow()
                                        } else {
                                            val target = selectedProxy ?: app.proxyStateStore.load() ?: run {
                                                val cached = app.serverListClient.loadCachedCountries()
                                                ServerListClient.candidatesForCountry(cached, RECOMMENDED_COUNTRY_CODE).firstOrNull()
                                                    ?: cached.firstOrNull { it.code.isNotBlank() }?.let { country ->
                                                        ServerListClient.candidatesForCountry(cached, country.code).firstOrNull()
                                                    }
                                            }
                                            if (target != null) {
                                                disconnectedPingLatency = PingUtil.measureTcpLatencyMs(target.host, target.port)
                                            }
                                        }
                                        isPinging = false
                                    }
                                }
                            },
                        horizontalAlignment = Alignment.CenterHorizontally,
                    ) {
                        Box(
                            modifier = Modifier
                                .size(38.dp)
                                .clip(CircleShape)
                                .background(chipBg),
                            contentAlignment = Alignment.Center,
                        ) {
                            Icon(
                                imageVector = Icons.Filled.SignalCellularAlt,
                                contentDescription = null,
                                tint = if (onYellow) Color.White else Color.White.copy(alpha = 0.85f),
                                modifier = Modifier.size(17.dp),
                            )
                        }
                        Spacer(Modifier.height(8.dp))
                        Text(
                            "Ping",
                            style = TextStyle(
                                fontFamily = PoppinsFamily,
                                fontWeight = FontWeight.Normal,
                                fontSize = 12.sp,
                            ),
                            color = muted,
                        )
                        Spacer(Modifier.height(2.dp))
                        val currentPing = if (connected) pingLatency else disconnectedPingLatency
                        Text(
                            text = when {
                                isPinging -> "\u2026"
                                currentPing != null -> "$currentPing ms"
                                else -> "\u2014"
                            },
                            style = TextStyle(
                                fontFamily = PoppinsFamily,
                                fontWeight = FontWeight.SemiBold,
                                fontSize = 16.sp,
                            ),
                            color = if (currentPing != null) (if (onYellow) IFoxyInk else IFoxyGreen) else ink,
                        )
                    }
                }

                // Guardian quota pill (connected, when the account reports one).
                if (connected && (isUnlimited || quotaRemaining != null || quotaMax != null)) {
                    Spacer(Modifier.height(20.dp))
                    Box(
                        modifier = Modifier
                            .align(Alignment.CenterHorizontally)
                            .clip(RoundedCornerShape(50))
                            .background(Color.White.copy(alpha = 0.38f))
                            .padding(horizontal = 18.dp, vertical = 9.dp),
                    ) {
                        Text(
                            text = when {
                                isUnlimited -> "Unlimited data on your account"
                                quotaRemaining != null && quotaMax != null ->
                                    "${formatBytes(quotaRemaining!!)} of ${formatBytes(quotaMax!!)} data remaining"
                                quotaRemaining != null -> "${formatBytes(quotaRemaining!!)} data remaining"
                                else -> "Limited to ${formatBytes(quotaMax!!)}"
                            },
                            style = TextStyle(
                                fontFamily = PoppinsFamily,
                                fontWeight = FontWeight.Medium,
                                fontSize = 12.5.sp,
                            ),
                            color = IFoxyInk.copy(alpha = 0.85f),
                        )
                    }
                }

                Spacer(Modifier.height(26.dp))
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(58.dp)
                        .clip(RoundedCornerShape(29.dp))
                        .background(if (connected) IFoxyInk else IFoxyYellow)
                        .clickable(role = Role.Button, onClick = onOpenServers)
                        .padding(horizontal = 20.dp),
                ) {
                    Row(
                        modifier = Modifier.fillMaxSize(),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Icon(
                            imageVector = Icons.Filled.LocationOn,
                            contentDescription = null,
                            tint = if (connected) Color.White else IFoxyInk,
                            modifier = Modifier.size(19.dp),
                        )
                        Spacer(Modifier.width(10.dp))
                        Text(
                            "Select Location",
                            style = TextStyle(
                                fontFamily = PoppinsFamily,
                                fontWeight = FontWeight.SemiBold,
                                fontSize = 15.5.sp,
                            ),
                            color = if (connected) Color.White else IFoxyInk,
                        )
                        Spacer(Modifier.weight(1f))
                        Icon(
                            imageVector = Icons.AutoMirrored.Filled.KeyboardArrowRight,
                            contentDescription = null,
                            tint = if (connected) Color.White else IFoxyInk,
                            modifier = Modifier.size(19.dp),
                        )
                    }
                }

                Spacer(Modifier.height(14.dp))
                Text(
                    "Protected by your Firefox account",
                    style = TextStyle(
                        fontFamily = PoppinsFamily,
                        fontWeight = FontWeight.Normal,
                        fontSize = 12.sp,
                    ),
                    color = muted,
                    modifier = Modifier.align(Alignment.CenterHorizontally),
                )
                Spacer(Modifier.height(28.dp))
            }
        }
    }
}

private fun formatDuration(seconds: Long): String {
    val h = seconds / 3600
    val m = (seconds % 3600) / 60
    val s = seconds % 60
    return String.format(Locale.US, "%02d:%02d:%02d", h, m, s)
}
