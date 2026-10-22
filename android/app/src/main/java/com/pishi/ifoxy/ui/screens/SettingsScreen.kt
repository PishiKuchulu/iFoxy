package com.pishi.ifoxy.ui.screens

import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.net.Uri
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.KeyboardArrowRight
import androidx.compose.material.icons.automirrored.filled.Logout
import androidx.compose.material.icons.filled.Code
import androidx.compose.material.icons.filled.ExpandMore
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import com.pishi.ifoxy.BuildConfig
import com.pishi.ifoxy.data.SettingsStore
import com.pishi.ifoxy.ui.components.AppUpdateController
import com.pishi.ifoxy.ui.components.UpdateUiState
import com.pishi.ifoxy.ui.theme.IFoxyBgDark
import com.pishi.ifoxy.ui.theme.IFoxyCardDark
import com.pishi.ifoxy.ui.theme.IFoxyInk
import com.pishi.ifoxy.ui.theme.IFoxyYellow
import com.pishi.ifoxy.ui.theme.PoppinsFamily
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

private const val GITHUB_URL = "https://github.com/PishiKuchulu/iFoxy"

@Composable
fun SettingsScreen(
    settingsStore: SettingsStore,
    darkTheme: Boolean,
    updateController: AppUpdateController,
    onOpenLogs: () -> Unit,
    onSignOut: () -> Unit,
    onBack: () -> Unit,
) {
    val context = LocalContext.current
    var exitCheckEnabled by remember { mutableStateOf(settingsStore.exitCheckEnabled) }
    var dnsProvider by remember { mutableStateOf(settingsStore.dnsProvider) }
    var customDohUrl by remember { mutableStateOf(settingsStore.customDohUrl) }
    var bootstrapDnsProvider by remember { mutableStateOf(settingsStore.bootstrapDnsProvider) }
    var customBootstrapIp by remember { mutableStateOf(settingsStore.customBootstrapIp) }
    var socksBindAddress by remember { mutableStateOf(settingsStore.socksBindAddress) }
    var socksPort by remember { mutableStateOf(settingsStore.socksPort) }
    var httpProxyEnabled by remember { mutableStateOf(settingsStore.httpProxyEnabled) }
    var httpProxyPort by remember { mutableStateOf(settingsStore.httpProxyPort) }
    var proxyOnlyMode by remember { mutableStateOf(settingsStore.proxyOnlyMode) }
    var customEdgeAddress by remember { mutableStateOf(settingsStore.customEdgeAddress) }
    var upstreamProxyEnabled by remember { mutableStateOf(settingsStore.upstreamProxyEnabled) }
    var upstreamProxyType by remember { mutableStateOf(settingsStore.upstreamProxyType) }
    var upstreamProxyHost by remember { mutableStateOf(settingsStore.upstreamProxyHost) }
    var upstreamProxyPort by remember { mutableStateOf(settingsStore.upstreamProxyPort) }
    var upstreamProxyUsername by remember { mutableStateOf(settingsStore.upstreamProxyUsername) }
    var upstreamProxyPassword by remember { mutableStateOf(settingsStore.upstreamProxyPassword) }
    var excludedApps by remember { mutableStateOf(settingsStore.excludedApps) }
    var mtu by remember { mutableStateOf(settingsStore.mtu) }
    var showDnsProviderDialog by remember { mutableStateOf(false) }
    var showBootstrapDnsDialog by remember { mutableStateOf(false) }
    var showMtuDialog by remember { mutableStateOf(false) }
    var showSocksBindDialog by remember { mutableStateOf(false) }
    var showSocksPortDialog by remember { mutableStateOf(false) }
    var showHttpPortDialog by remember { mutableStateOf(false) }
    var showEdgeAddressDialog by remember { mutableStateOf(false) }
    var showUpstreamProxyTypeDialog by remember { mutableStateOf(false) }
    var showUpstreamProxyAddressDialog by remember { mutableStateOf(false) }
    var showUpstreamProxyCredentialsDialog by remember { mutableStateOf(false) }
    var showSplitTunnelDialog by remember { mutableStateOf(false) }
    var tlsSplitMode by remember { mutableStateOf(settingsStore.tlsSplitMode) }
    var showTlsSplitDialog by remember { mutableStateOf(false) }

    if (showMtuDialog) {
        MtuPickerDialog(
            current = mtu,
            onDismiss = { showMtuDialog = false },
            onConfirm = {
                mtu = it
                settingsStore.mtu = it
                showMtuDialog = false
            },
        )
    }

    if (showDnsProviderDialog) {
        DnsProviderPickerDialog(
            currentProvider = dnsProvider,
            currentCustomUrl = customDohUrl,
            onDismiss = { showDnsProviderDialog = false },
            onConfirm = { provider, url ->
                dnsProvider = provider
                settingsStore.dnsProvider = provider
                customDohUrl = url
                settingsStore.customDohUrl = url
                showDnsProviderDialog = false
            },
        )
    }
    if (showBootstrapDnsDialog) {
        BootstrapDnsPickerDialog(
            currentProvider = bootstrapDnsProvider,
            currentCustomIp = customBootstrapIp,
            onDismiss = { showBootstrapDnsDialog = false },
            onConfirm = { provider, ip ->
                bootstrapDnsProvider = provider
                settingsStore.bootstrapDnsProvider = provider
                customBootstrapIp = ip
                settingsStore.customBootstrapIp = ip
                showBootstrapDnsDialog = false
            },
        )
    }
    if (showSocksBindDialog) {
        SocksBindAddressPickerDialog(
            current = socksBindAddress,
            onDismiss = { showSocksBindDialog = false },
            onConfirm = {
                socksBindAddress = it
                settingsStore.socksBindAddress = it
                showSocksBindDialog = false
            },
        )
    }
    if (showSocksPortDialog) {
        SocksPortPickerDialog(
            current = socksPort,
            onDismiss = { showSocksPortDialog = false },
            onConfirm = {
                socksPort = it
                settingsStore.socksPort = it
                showSocksPortDialog = false
            },
        )
    }
    if (showHttpPortDialog) {
        HttpPortPickerDialog(
            current = httpProxyPort,
            onDismiss = { showHttpPortDialog = false },
            onConfirm = {
                httpProxyPort = it
                settingsStore.httpProxyPort = it
                showHttpPortDialog = false
            },
        )
    }
    if (showEdgeAddressDialog) {
        CustomEdgeAddressDialog(
            current = customEdgeAddress,
            onDismiss = { showEdgeAddressDialog = false },
            onConfirm = {
                customEdgeAddress = it
                settingsStore.customEdgeAddress = it
                showEdgeAddressDialog = false
            },
        )
    }
    if (showUpstreamProxyTypeDialog) {
        UpstreamProxyTypePickerDialog(
            current = upstreamProxyType,
            onDismiss = { showUpstreamProxyTypeDialog = false },
            onConfirm = {
                upstreamProxyType = it
                settingsStore.upstreamProxyType = it
                showUpstreamProxyTypeDialog = false
            },
        )
    }
    if (showUpstreamProxyAddressDialog) {
        UpstreamProxyAddressDialog(
            currentHost = upstreamProxyHost,
            currentPort = upstreamProxyPort,
            onDismiss = { showUpstreamProxyAddressDialog = false },
            onConfirm = { host, port ->
                upstreamProxyHost = host
                upstreamProxyPort = port
                settingsStore.upstreamProxyHost = host
                settingsStore.upstreamProxyPort = port
                showUpstreamProxyAddressDialog = false
            },
        )
    }
    if (showUpstreamProxyCredentialsDialog) {
        UpstreamProxyCredentialsDialog(
            currentUsername = upstreamProxyUsername,
            currentPassword = upstreamProxyPassword,
            onDismiss = { showUpstreamProxyCredentialsDialog = false },
            onConfirm = { username, password ->
                upstreamProxyUsername = username
                upstreamProxyPassword = password
                settingsStore.upstreamProxyUsername = username
                settingsStore.upstreamProxyPassword = password
                showUpstreamProxyCredentialsDialog = false
            },
        )
    }
    if (showSplitTunnelDialog) {
        SplitTunnelDialog(
            current = excludedApps,
            onDismiss = { showSplitTunnelDialog = false },
            onConfirm = {
                excludedApps = it
                settingsStore.excludedApps = it
                showSplitTunnelDialog = false
            },
        )
    }
    if (showTlsSplitDialog) {
        TlsSplitModePickerDialog(
            current = tlsSplitMode,
            onDismiss = { showTlsSplitDialog = false },
            onConfirm = {
                tlsSplitMode = it
                settingsStore.tlsSplitMode = it
                showTlsSplitDialog = false
            },
        )
    }

    Scaffold(
        containerColor = if (darkTheme) IFoxyBgDark else IFoxyYellow,
        topBar = {
            TopAppBar(
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = if (darkTheme) IFoxyBgDark else IFoxyYellow,
                    titleContentColor = if (darkTheme) Color.White else IFoxyInk,
                    navigationIconContentColor = if (darkTheme) Color.White else IFoxyInk,
                ),
                title = { Text("Settings", fontFamily = PoppinsFamily, fontWeight = FontWeight.SemiBold) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
    ) { padding ->
        Column(
            Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Spacer(Modifier.height(2.dp))
            SettingsSection(title = "Connection", darkTheme = darkTheme, initiallyExpanded = true) {
            ListItem(
                headlineContent = { Text("Verify exit location") },
                supportingContent = { Text("Check that the tunnel exits in the selected country") },
                trailingContent = {
                    Switch(
                        checked = exitCheckEnabled,
                        onCheckedChange = {
                            exitCheckEnabled = it
                            settingsStore.exitCheckEnabled = it
                        },
                    )
                },
            )
            ListItem(
                headlineContent = { Text("Tunnel MTU") },
                supportingContent = { Text(mtu.toString()) },
                trailingContent = { Icon(Icons.AutoMirrored.Filled.KeyboardArrowRight, contentDescription = null) },
                modifier = Modifier.clickable { showMtuDialog = true },
            )

            }
            SettingsSection(title = "DNS", darkTheme = darkTheme) {
            ListItem(
                headlineContent = { Text("Tunnel DNS") },
                supportingContent = {
                    val subtitle = when (dnsProvider) {
                        SettingsStore.DnsProvider.SYSTEM_DEFAULT -> "Default"
                        SettingsStore.DnsProvider.CUSTOM -> customDohUrl.ifBlank { "Custom DoH (Not configured)" }
                        else -> dnsProvider.label
                    }
                    Text(subtitle)
                },
                trailingContent = { Icon(Icons.AutoMirrored.Filled.KeyboardArrowRight, contentDescription = null) },
                modifier = Modifier.clickable { showDnsProviderDialog = true },
            )
            ListItem(
                headlineContent = { Text("Resolver DNS") },
                supportingContent = {
                    val subtitle = when (bootstrapDnsProvider) {
                        SettingsStore.BootstrapDnsProvider.CUSTOM -> customBootstrapIp.ifBlank { "Custom IP (Not configured)" }
                        SettingsStore.BootstrapDnsProvider.SYSTEM -> "System DNS"
                        else -> bootstrapDnsProvider.label
                    }
                    Text(subtitle)
                },
                trailingContent = { Icon(Icons.AutoMirrored.Filled.KeyboardArrowRight, contentDescription = null) },
                modifier = Modifier.clickable { showBootstrapDnsDialog = true },
            )

            }
            SettingsSection(title = "Local proxy", darkTheme = darkTheme) {
            ListItem(
                headlineContent = { Text("Proxy-only mode") },
                supportingContent = { Text("Run local proxy servers (SOCKS5 & HTTP), without a VPN interface") },
                trailingContent = {
                    Switch(
                        checked = proxyOnlyMode,
                        onCheckedChange = {
                            proxyOnlyMode = it
                            settingsStore.proxyOnlyMode = it
                        },
                    )
                },
            )
            ListItem(
                headlineContent = { Text("Local address") },
                supportingContent = { Text(socksBindAddress) },
                trailingContent = { Icon(Icons.AutoMirrored.Filled.KeyboardArrowRight, contentDescription = null) },
                modifier = Modifier.clickable { showSocksBindDialog = true },
            )
            ListItem(
                headlineContent = { Text("SOCKS5 port") },
                supportingContent = { Text(socksPort.toString()) },
                trailingContent = { Icon(Icons.AutoMirrored.Filled.KeyboardArrowRight, contentDescription = null) },
                modifier = Modifier.clickable { showSocksPortDialog = true },
            )
            ListItem(
                headlineContent = { Text("Enable HTTP proxy") },
                supportingContent = { Text("Run local HTTP proxy alongside SOCKS5") },
                trailingContent = {
                    Switch(
                        checked = httpProxyEnabled,
                        onCheckedChange = {
                            httpProxyEnabled = it
                            settingsStore.httpProxyEnabled = it
                        },
                    )
                },
            )
            if (httpProxyEnabled) {
                ListItem(
                    headlineContent = { Text("HTTP port") },
                    supportingContent = { Text(httpProxyPort.toString()) },
                    trailingContent = { Icon(Icons.AutoMirrored.Filled.KeyboardArrowRight, contentDescription = null) },
                    modifier = Modifier.clickable { showHttpPortDialog = true },
                )
            }

            }
            SettingsSection(title = "Split tunneling", darkTheme = darkTheme) {
            ListItem(
                headlineContent = { Text("Excluded apps") },
                supportingContent = {
                    Text(
                        if (excludedApps.isEmpty()) {
                            "None"
                        } else {
                            "${excludedApps.size} app(s) bypass the VPN"
                        },
                    )
                },
                trailingContent = { Icon(Icons.AutoMirrored.Filled.KeyboardArrowRight, contentDescription = null) },
                modifier = Modifier.clickable { showSplitTunnelDialog = true },
            )

            }
            SettingsSection(title = "Advanced", darkTheme = darkTheme) {
            ListItem(
                headlineContent = { Text("Custom edge address") },
                supportingContent = { Text(customEdgeAddress.ifBlank { "Not set" }) },
                trailingContent = { Icon(Icons.AutoMirrored.Filled.KeyboardArrowRight, contentDescription = null) },
                modifier = Modifier.clickable { showEdgeAddressDialog = true },
            )
            ListItem(
                headlineContent = { Text("TLS fragmentation") },
                supportingContent = { Text(tlsSplitMode.label) },
                trailingContent = { Icon(Icons.AutoMirrored.Filled.KeyboardArrowRight, contentDescription = null) },
                modifier = Modifier.clickable { showTlsSplitDialog = true },
            )
            ListItem(
                headlineContent = { Text("Chain through upstream proxy") },
                supportingContent = { Text("Connect to the VPN server through another proxy first") },
                trailingContent = {
                    Switch(
                        checked = upstreamProxyEnabled,
                        onCheckedChange = {
                            upstreamProxyEnabled = it
                            settingsStore.upstreamProxyEnabled = it
                        },
                    )
                },
            )
            if (upstreamProxyEnabled) {
                ListItem(
                    headlineContent = { Text("Proxy type") },
                    supportingContent = { Text(upstreamProxyType.name) },
                    trailingContent = { Icon(Icons.AutoMirrored.Filled.KeyboardArrowRight, contentDescription = null) },
                    modifier = Modifier.clickable { showUpstreamProxyTypeDialog = true },
                )
                ListItem(
                    headlineContent = { Text("Proxy address") },
                    supportingContent = {
                        Text(
                            if (upstreamProxyHost.isBlank()) {
                                "Not set"
                            } else {
                                "$upstreamProxyHost:$upstreamProxyPort"
                            },
                        )
                    },
                    trailingContent = { Icon(Icons.AutoMirrored.Filled.KeyboardArrowRight, contentDescription = null) },
                    modifier = Modifier.clickable { showUpstreamProxyAddressDialog = true },
                )
                ListItem(
                    headlineContent = { Text("Proxy credentials") },
                    supportingContent = {
                        Text(if (upstreamProxyUsername.isBlank()) "None" else upstreamProxyUsername)
                    },
                    trailingContent = { Icon(Icons.AutoMirrored.Filled.KeyboardArrowRight, contentDescription = null) },
                    modifier = Modifier.clickable { showUpstreamProxyCredentialsDialog = true },
                )
            }

            }
            SettingsSection(title = "About", darkTheme = darkTheme) {
            ListItem(
                headlineContent = { Text("View logs") },
                supportingContent = { Text("Recent connection activity") },
                trailingContent = { Icon(Icons.AutoMirrored.Filled.KeyboardArrowRight, contentDescription = null) },
                modifier = Modifier.clickable(onClick = onOpenLogs),
            )
            ListItem(
                headlineContent = { Text("Version") },
                supportingContent = { Text(BuildConfig.VERSION_NAME) },
            )
            ListItem(
                headlineContent = { Text("App update") },
                supportingContent = {
                    val updateState = updateController.state
                    Text(
                        when (updateState) {
                            is UpdateUiState.Available -> "Update available: v${updateState.info.version}"
                            is UpdateUiState.Checking -> "Checking for updates\u2026"
                            is UpdateUiState.Downloading -> {
                                val pct = if (updateState.total > 0) {
                                    (updateState.downloaded * 100 / updateState.total).toInt()
                                } else {
                                    0
                                }
                                "Downloading update\u2026 $pct%"
                            }
                            is UpdateUiState.ReadyToInstall -> "v${updateState.info.version} ready to install"
                            is UpdateUiState.UpToDate -> "You're up to date"
                            is UpdateUiState.Failed -> "Update check failed"
                            else -> "Check GitHub releases for a newer version"
                        },
                    )
                },
                trailingContent = {
                    TextButton(
                        onClick = {
                            when (updateController.state) {
                                is UpdateUiState.Available,
                                is UpdateUiState.ReadyToInstall,
                                is UpdateUiState.Failed -> updateController.showDialog()
                                else -> updateController.check()
                            }
                        },
                    ) {
                        Text(
                            when (updateController.state) {
                                is UpdateUiState.Available -> "Download"
                                is UpdateUiState.ReadyToInstall -> "Install"
                                else -> "Check"
                            },
                        )
                    }
                },
            )
            ListItem(
                headlineContent = { Text("Source code") },
                supportingContent = { Text(GITHUB_URL) },
                leadingContent = { Icon(Icons.Filled.Code, contentDescription = null) },
                modifier = Modifier.clickable {
                    context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(GITHUB_URL)))
                },
            )

            }
            SettingsSection(title = "Account", darkTheme = darkTheme) {
            Button(
                onClick = onSignOut,
                colors = ButtonDefaults.buttonColors(
                    containerColor = MaterialTheme.colorScheme.errorContainer,
                    contentColor = MaterialTheme.colorScheme.onErrorContainer,
                ),
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 8.dp),
            ) {
                Icon(Icons.AutoMirrored.Filled.Logout, contentDescription = null)
                Spacer(Modifier.width(8.dp))
                Text("Sign out")
            }
            }
            Spacer(Modifier.height(4.dp))
        }
    }
}

@Composable
private fun DnsProviderPickerDialog(
    currentProvider: SettingsStore.DnsProvider,
    currentCustomUrl: String,
    onDismiss: () -> Unit,
    onConfirm: (SettingsStore.DnsProvider, String) -> Unit,
) {
    var selectedProvider by remember { mutableStateOf(currentProvider) }
    var urlText by remember { mutableStateOf(currentCustomUrl) }
    val isCustom = selectedProvider == SettingsStore.DnsProvider.CUSTOM
    val isValidCustomUrl = SettingsStore.isValidDohUrl(urlText)
    val canSave = !isCustom || isValidCustomUrl

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Tunnel DNS") },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState())) {
                Text(
                    "DNS used inside the VPN tunnel for all app and browsing traffic.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(bottom = 8.dp),
                )
                SettingsStore.DnsProvider.entries.forEach { provider ->
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        modifier = Modifier
                            .fillMaxWidth()
                            .selectable(
                                selected = selectedProvider == provider,
                                onClick = { selectedProvider = provider },
                            )
                            .padding(vertical = 4.dp),
                    ) {
                        RadioButton(
                            selected = selectedProvider == provider,
                            onClick = { selectedProvider = provider },
                        )
                        Column(Modifier.padding(start = 8.dp)) {
                            Text(provider.label)
                            val detail = when (provider) {
                                SettingsStore.DnsProvider.SYSTEM_DEFAULT -> "Resolved at the VPN edge"
                                SettingsStore.DnsProvider.CUSTOM -> "Specify an HTTPS DoH endpoint URL"
                                else -> provider.dohUrl ?: ""
                            }
                            if (detail.isNotEmpty()) {
                                Text(
                                    detail,
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                            }
                        }
                    }
                }
                if (isCustom) {
                    OutlinedTextField(
                        value = urlText,
                        onValueChange = { urlText = it.trim() },
                        label = { Text("DoH URL (https://...)") },
                        placeholder = { Text("https://example.com/dns-query") },
                        singleLine = true,
                        isError = urlText.isNotBlank() && !isValidCustomUrl,
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(top = 8.dp),
                    )
                }
            }
        },
        confirmButton = {
            TextButton(
                onClick = { onConfirm(selectedProvider, urlText) },
                enabled = canSave,
            ) {
                Text("Save")
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text("Cancel") }
        },
    )
}

@Composable
private fun BootstrapDnsPickerDialog(
    currentProvider: SettingsStore.BootstrapDnsProvider,
    currentCustomIp: String,
    onDismiss: () -> Unit,
    onConfirm: (SettingsStore.BootstrapDnsProvider, String) -> Unit,
) {
    var selectedProvider by remember { mutableStateOf(currentProvider) }
    var ipText by remember { mutableStateOf(currentCustomIp) }
    val isCustom = selectedProvider == SettingsStore.BootstrapDnsProvider.CUSTOM
    val isValidCustomIp = SettingsStore.isValidIpAddress(ipText.trim())
    val canSave = !isCustom || isValidCustomIp

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Resolver DNS") },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState())) {
                Text(
                    "DNS used to resolve the VPN server address before the tunnel connects.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(bottom = 8.dp),
                )
                SettingsStore.BootstrapDnsProvider.entries.forEach { provider ->
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        modifier = Modifier
                            .fillMaxWidth()
                            .selectable(
                                selected = selectedProvider == provider,
                                onClick = { selectedProvider = provider },
                            )
                            .padding(vertical = 4.dp),
                    ) {
                        RadioButton(
                            selected = selectedProvider == provider,
                            onClick = { selectedProvider = provider },
                        )
                        Column(Modifier.padding(start = 8.dp)) {
                            Text(provider.label)
                            Text(
                                provider.description,
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                    }
                }
                if (isCustom) {
                    OutlinedTextField(
                        value = ipText,
                        onValueChange = { ipText = it.trim() },
                        label = { Text("Resolver IP address") },
                        placeholder = { Text("e.g. 76.76.2.2") },
                        singleLine = true,
                        isError = ipText.isNotBlank() && !isValidCustomIp,
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Ascii),
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(top = 8.dp),
                    )
                }
            }
        },
        confirmButton = {
            TextButton(
                onClick = { onConfirm(selectedProvider, ipText.trim()) },
                enabled = canSave,
            ) {
                Text("Save")
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text("Cancel") }
        },
    )
}

@Composable
private fun CustomEdgeAddressDialog(
    current: String,
    onDismiss: () -> Unit,
    onConfirm: (String) -> Unit,
) {
    var value by remember { mutableStateOf(current) }
    val trimmed = value.trim()
    val isValid = trimmed.isEmpty() || SettingsStore.isValidEdgeHost(trimmed)

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Custom edge address") },
        text = {
            Column {
                OutlinedTextField(
                    value = value,
                    onValueChange = { value = it },
                    label = { Text("Host or IP") },
                    singleLine = true,
                    isError = !isValid,
                )
                Text(
                    "Leave empty to resolve the server hostname normally.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(top = 8.dp),
                )
            }
        },
        confirmButton = {
            TextButton(onClick = { onConfirm(trimmed) }, enabled = isValid) { Text("Save") }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text("Cancel") }
        },
    )
}

@Composable
private fun SocksBindAddressPickerDialog(
    current: String,
    onDismiss: () -> Unit,
    onConfirm: (String) -> Unit,
) {
    var selected by remember { mutableStateOf(current) }
    // SEC-FX-05: binding to a non-loopback address turns the phone into an
    // unauthenticated open proxy on the local network. That choice needs an
    // explicit risk confirmation, not a silent save.
    var showOpenProxyWarning by remember { mutableStateOf(false) }

    if (showOpenProxyWarning) {
        AlertDialog(
            onDismissRequest = { showOpenProxyWarning = false },
            title = { Text("Open proxy warning") },
            text = {
                Text(
                    "The local proxies have no authentication. Binding to $selected means anyone " +
                        "on your local network can use your connection and your Mozilla account's " +
                        "traffic allowance through this device, and their traffic will appear to " +
                        "come from you. Only continue on a network you fully trust.",
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    showOpenProxyWarning = false
                    onConfirm(selected)
                }) { Text("I understand, enable") }
            },
            dismissButton = {
                TextButton(onClick = { showOpenProxyWarning = false }) { Text("Cancel") }
            },
        )
        return
    }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Local address") },
        text = {
            Column {
                SettingsStore.SOCKS_BIND_ADDRESS_PRESETS.forEach { (address, label) ->
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        modifier = Modifier
                            .fillMaxWidth()
                            .selectable(selected = selected == address, onClick = { selected = address })
                            .padding(vertical = 4.dp),
                    ) {
                        RadioButton(selected = selected == address, onClick = { selected = address })
                        Text(label, modifier = Modifier.padding(start = 8.dp))
                    }
                }
            }
        },
        confirmButton = {
            TextButton(onClick = {
                if (selected != "127.0.0.1" && selected != current) {
                    showOpenProxyWarning = true
                } else {
                    onConfirm(selected)
                }
            }) { Text("Save") }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text("Cancel") }
        },
    )
}

@Composable
private fun SocksPortPickerDialog(
    current: Int,
    onDismiss: () -> Unit,
    onConfirm: (Int) -> Unit,
) {
    var portText by remember { mutableStateOf(current.toString()) }
    val parsedPort = portText.toIntOrNull()
    val isValid = parsedPort != null && parsedPort in 1..65_535

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Local port") },
        text = {
            OutlinedTextField(
                value = portText,
                onValueChange = { portText = it.filter(Char::isDigit).take(5) },
                label = { Text("Port (1\u201365535)") },
                singleLine = true,
                isError = portText.isNotBlank() && !isValid,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
            )
        },
        confirmButton = {
            TextButton(onClick = { parsedPort?.let { onConfirm(it) } }, enabled = isValid) { Text("Save") }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text("Cancel") }
        },
    )
}

@Composable
private fun HttpPortPickerDialog(
    current: Int,
    onDismiss: () -> Unit,
    onConfirm: (Int) -> Unit,
) {
    var portText by remember { mutableStateOf(current.toString()) }
    val parsedPort = portText.toIntOrNull()
    val isValid = parsedPort != null && parsedPort in 1..65_535

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("HTTP port") },
        text = {
            OutlinedTextField(
                value = portText,
                onValueChange = { portText = it.filter(Char::isDigit).take(5) },
                label = { Text("Port (1\u201365535)") },
                singleLine = true,
                isError = portText.isNotBlank() && !isValid,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
            )
        },
        confirmButton = {
            TextButton(onClick = { parsedPort?.let { onConfirm(it) } }, enabled = isValid) { Text("Save") }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text("Cancel") }
        },
    )
}

@Composable
private fun UpstreamProxyTypePickerDialog(
    current: SettingsStore.UpstreamProxyType,
    onDismiss: () -> Unit,
    onConfirm: (SettingsStore.UpstreamProxyType) -> Unit,
) {
    var selected by remember { mutableStateOf(current) }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Proxy type") },
        text = {
            Column {
                SettingsStore.UpstreamProxyType.entries.forEach { type ->
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        modifier = Modifier
                            .fillMaxWidth()
                            .selectable(selected = selected == type, onClick = { selected = type })
                            .padding(vertical = 4.dp),
                    ) {
                        RadioButton(selected = selected == type, onClick = { selected = type })
                        Text(type.name, modifier = Modifier.padding(start = 8.dp))
                    }
                }
            }
        },
        confirmButton = {
            TextButton(onClick = { onConfirm(selected) }) { Text("Save") }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text("Cancel") }
        },
    )
}

@Composable
private fun TlsSplitModePickerDialog(
    current: SettingsStore.TlsSplitMode,
    onDismiss: () -> Unit,
    onConfirm: (SettingsStore.TlsSplitMode) -> Unit,
) {
    var selected by remember { mutableStateOf(current) }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("TLS fragmentation") },
        text = {
            Column {
                Text(
                    "Fragments the TLS ClientHello into multiple TCP packets to bypass SNI-based filtering on censored networks.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(bottom = 12.dp),
                )
                SettingsStore.TlsSplitMode.entries.forEach { mode ->
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        modifier = Modifier
                            .fillMaxWidth()
                            .selectable(selected = selected == mode, onClick = { selected = mode })
                            .padding(vertical = 6.dp),
                    ) {
                        RadioButton(selected = selected == mode, onClick = { selected = mode })
                        Column(Modifier.padding(start = 8.dp)) {
                            Text(mode.label, style = MaterialTheme.typography.bodyLarge)
                            Text(
                                mode.description,
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                    }
                }
            }
        },
        confirmButton = {
            TextButton(onClick = { onConfirm(selected) }) { Text("Save") }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text("Cancel") }
        },
    )
}

@Composable
private fun UpstreamProxyAddressDialog(
    currentHost: String,
    currentPort: Int,
    onDismiss: () -> Unit,
    onConfirm: (String, Int) -> Unit,
) {
    var host by remember { mutableStateOf(currentHost) }
    var portText by remember { mutableStateOf(currentPort.toString()) }
    val parsedPort = portText.toIntOrNull()
    val isValid = host.isNotBlank() && parsedPort != null && parsedPort in 1..65_535

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Proxy address") },
        text = {
            Column {
                OutlinedTextField(
                    value = host,
                    onValueChange = { host = it.trim() },
                    label = { Text("Host or IP") },
                    singleLine = true,
                )
                OutlinedTextField(
                    value = portText,
                    onValueChange = { portText = it.filter(Char::isDigit).take(5) },
                    label = { Text("Port (1\u201365535)") },
                    singleLine = true,
                    isError = portText.isNotBlank() && (parsedPort == null || parsedPort !in 1..65_535),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                    modifier = Modifier.padding(top = 8.dp),
                )
            }
        },
        confirmButton = {
            TextButton(onClick = { parsedPort?.let { onConfirm(host, it) } }, enabled = isValid) { Text("Save") }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text("Cancel") }
        },
    )
}

@Composable
private fun UpstreamProxyCredentialsDialog(
    currentUsername: String,
    currentPassword: String,
    onDismiss: () -> Unit,
    onConfirm: (String, String) -> Unit,
) {
    var username by remember { mutableStateOf(currentUsername) }
    var password by remember { mutableStateOf(currentPassword) }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Proxy credentials") },
        text = {
            Column {
                OutlinedTextField(
                    value = username,
                    onValueChange = { username = it },
                    label = { Text("Username (optional)") },
                    singleLine = true,
                )
                OutlinedTextField(
                    value = password,
                    onValueChange = { password = it },
                    label = { Text("Password (optional)") },
                    singleLine = true,
                    visualTransformation = PasswordVisualTransformation(),
                    modifier = Modifier.padding(top = 8.dp),
                )
            }
        },
        confirmButton = {
            TextButton(onClick = { onConfirm(username, password) }) { Text("Save") }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text("Cancel") }
        },
    )
}

private data class InstalledAppEntry(val packageName: String, val label: String)

@Composable
private fun SplitTunnelDialog(
    current: Set<String>,
    onDismiss: () -> Unit,
    onConfirm: (Set<String>) -> Unit,
) {
    val context = LocalContext.current
    var selected by remember { mutableStateOf(current) }
    var searchQuery by remember { mutableStateOf("") }

    val installedApps by produceState<List<InstalledAppEntry>>(initialValue = emptyList()) {
        value = withContext(Dispatchers.IO) {
            val packageManager = context.packageManager
            packageManager.getInstalledApplications(PackageManager.GET_META_DATA)
                .asSequence()
                .filter { it.packageName != context.packageName }
                .filter { packageManager.getLaunchIntentForPackage(it.packageName) != null }
                .map { info: ApplicationInfo ->
                    InstalledAppEntry(info.packageName, info.loadLabel(packageManager).toString())
                }
                .sortedBy { it.label.lowercase() }
                .toList()
        }
    }
    val filteredApps = remember(installedApps, searchQuery) {
        if (searchQuery.isBlank()) {
            installedApps
        } else {
            installedApps.filter { it.label.contains(searchQuery, ignoreCase = true) }
        }
    }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Split tunneling") },
        text = {
            Column {
                Text(
                    "Selected apps bypass the VPN and use your normal connection.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(bottom = 8.dp),
                )
                OutlinedTextField(
                    value = searchQuery,
                    onValueChange = { searchQuery = it },
                    label = { Text("Search apps") },
                    leadingIcon = { Icon(Icons.Filled.Search, contentDescription = null) },
                    singleLine = true,
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(bottom = 8.dp),
                )
                if (installedApps.isEmpty()) {
                    CircularProgressIndicator(
                        modifier = Modifier.padding(24.dp).align(Alignment.CenterHorizontally)
                    )
                } else if (filteredApps.isEmpty()) {
                    Text(
                        "No apps match \"$searchQuery\".",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(vertical = 12.dp),
                    )
                } else {
                    LazyColumn(modifier = Modifier.height(360.dp)) {
                        items(filteredApps, key = { it.packageName }) { app ->
                            val isChecked = selected.contains(app.packageName)
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .clickable {
                                        selected = if (isChecked) {
                                            selected - app.packageName
                                        } else {
                                            selected + app.packageName
                                        }
                                    }
                                    .padding(vertical = 2.dp),
                            ) {
                                Checkbox(
                                    checked = isChecked,
                                    onCheckedChange = {
                                        selected = if (it) selected + app.packageName else selected - app.packageName
                                    },
                                )
                                Text(app.label, modifier = Modifier.padding(start = 8.dp))
                            }
                        }
                    }
                }
            }
        },
        confirmButton = {
            TextButton(onClick = { onConfirm(selected) }) { Text("Save") }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text("Cancel") }
        },
    )
}

/**
 * One settings category as a brand card whose options open like a menu
 * when its header is tapped. The nested MaterialTheme re-points the M3
 * surface colors at the card, so the existing ListItem/Switch rows render
 * on the card in the app's brand palette (matching the Home screen).
 */
@Composable
private fun SettingsSection(
    title: String,
    darkTheme: Boolean,
    initiallyExpanded: Boolean = false,
    content: @Composable () -> Unit,
) {
    var expanded by rememberSaveable(title) { mutableStateOf(initiallyExpanded) }
    val cardColor = if (darkTheme) IFoxyCardDark else Color.White
    val inkColor = if (darkTheme) Color.White else IFoxyInk
    val mutedColor = if (darkTheme) Color.White.copy(alpha = 0.55f) else IFoxyInk.copy(alpha = 0.6f)
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(20.dp))
            .background(cardColor),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .clickable { expanded = !expanded }
                .padding(horizontal = 16.dp, vertical = 15.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(
                title,
                style = MaterialTheme.typography.titleMedium.copy(
                    fontFamily = PoppinsFamily,
                    fontWeight = FontWeight.SemiBold,
                ),
                color = inkColor,
                modifier = Modifier.weight(1f),
            )
            Icon(
                imageVector = Icons.Filled.ExpandMore,
                contentDescription = if (expanded) "Collapse $title" else "Expand $title",
                tint = mutedColor,
                modifier = Modifier.rotate(if (expanded) 180f else 0f),
            )
        }
        AnimatedVisibility(
            visible = expanded,
            enter = expandVertically() + fadeIn(),
            exit = shrinkVertically() + fadeOut(),
        ) {
            MaterialTheme(
                colorScheme = MaterialTheme.colorScheme.copy(
                    surface = cardColor,
                    surfaceVariant = cardColor,
                    onSurface = inkColor,
                    onSurfaceVariant = mutedColor,
                ),
                typography = MaterialTheme.typography,
                shapes = MaterialTheme.shapes,
            ) {
                Column { content() }
            }
        }
    }
}

@Composable
private fun MtuPickerDialog(
    current: Int,
    onDismiss: () -> Unit,
    onConfirm: (Int) -> Unit,
) {
    var mtuText by remember { mutableStateOf(current.toString()) }
    val parsedMtu = mtuText.toIntOrNull()
    val isValid = parsedMtu != null && parsedMtu in SettingsStore.MIN_MTU..SettingsStore.MAX_MTU

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Tunnel MTU") },
        text = {
            Column {
                Text(
                    "Maximum Transmission Unit for the VPN tunnel. Default is ${SettingsStore.DEFAULT_MTU}. Lower values (e.g. 1280\u20131400) prevent packet fragmentation on mobile networks.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(bottom = 12.dp),
                )
                OutlinedTextField(
                    value = mtuText,
                    onValueChange = { mtuText = it.filter(Char::isDigit).take(4) },
                    label = { Text("MTU (${SettingsStore.MIN_MTU}\u2013${SettingsStore.MAX_MTU})") },
                    singleLine = true,
                    isError = mtuText.isNotBlank() && !isValid,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                    modifier = Modifier.fillMaxWidth(),
                )
                TextButton(
                    onClick = { mtuText = SettingsStore.DEFAULT_MTU.toString() },
                    modifier = Modifier.align(Alignment.End),
                ) {
                    Text("Reset to default (${SettingsStore.DEFAULT_MTU})")
                }
            }
        },
        confirmButton = {
            TextButton(onClick = { parsedMtu?.let { onConfirm(it) } }, enabled = isValid) { Text("Save") }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text("Cancel") }
        },
    )
}
