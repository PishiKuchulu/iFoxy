package com.pishi.ifoxy.ui.navigation

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Modifier
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.launch
import androidx.navigation.NavHostController
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import com.pishi.ifoxy.IFoxyApp
import com.pishi.ifoxy.ui.components.AppUpdateController
import com.pishi.ifoxy.ui.components.AppUpdateDialog
import com.pishi.ifoxy.ui.screens.HomeScreen
import com.pishi.ifoxy.ui.screens.LoginScreen
import com.pishi.ifoxy.ui.screens.LogsScreen
import com.pishi.ifoxy.ui.screens.ServerListScreen
import com.pishi.ifoxy.ui.screens.SettingsScreen
import com.pishi.ifoxy.ui.screens.SplashScreen
import com.pishi.ifoxy.ui.theme.ThemeController

object IFoxyRoutes {
    const val SPLASH = "splash"
    const val LOGIN = "login"
    const val ADD_ACCOUNT = "add_account"
    const val HOME = "home"
    const val SERVERS = "servers"
    const val SETTINGS = "settings"
    const val LOGS = "logs"
}

@Composable
fun IFoxyNavGraph(
    navController: NavHostController = rememberNavController(),
    app: IFoxyApp,
    themeController: ThemeController,
    onRequestConnect: () -> Unit,
    onDisconnect: () -> Unit,
) {
    val updateController = remember { AppUpdateController(app) }
    val navScope = rememberCoroutineScope()
    LaunchedEffect(Unit) {
        updateController.checkOnLaunch()
        // Multi-account bootstrap: migrate a pre-existing (pre-vault)
        // session into the account vault, learning its email from FxA;
        // otherwise just harvest any refreshed tokens into the vault.
        if (app.accountStore.accounts().isEmpty() && app.tokenStore.hasStoredSession()) {
            val email = try {
                app.authRepository.fetchAccountEmail()
            } catch (cancellation: CancellationException) {
                throw cancellation
            } catch (unreachable: Exception) {
                null
            }
            val auth = app.tokenStore.loadAuth()
            if (email != null && auth != null) {
                app.accountStore.upsert(email, auth)
            }
        } else {
            app.accountSwitcher.harvestActive()
        }
    }

    fun fullSignOut() {
        onDisconnect()
        app.tokenStore.clear()
        app.accountStore.clear()
        app.settingsStore.clearAccountSession()
        app.proxyStateStore.clear()
        navController.navigate(IFoxyRoutes.LOGIN) {
            popUpTo(0) { inclusive = true }
        }
    }

    /** Sign out of the ACTIVE account: when other accounts are stored,
     *  the next one takes over (and the tunnel re-dials on it); with no
     *  accounts left this is a full sign-out. */
    fun signOutActiveAccount() {
        val activeId = app.accountStore.activeAccountId
        val others = app.accountStore.accounts().filter { it.id != activeId }
        if (activeId != null) app.accountStore.remove(activeId)
        if (others.isNotEmpty()) {
            app.accountSwitcher.activate(others.first().id)
            navScope.launch { app.accountSwitcher.restartTunnelIfRunning() }
        } else {
            fullSignOut()
        }
    }
    Box(Modifier.fillMaxSize()) {
    NavHost(navController = navController, startDestination = IFoxyRoutes.SPLASH) {
        composable(IFoxyRoutes.SPLASH) {
            SplashScreen(
                authRepository = app.authRepository,
                onSignedIn = {
                    navController.navigate(IFoxyRoutes.HOME) { popUpTo(IFoxyRoutes.SPLASH) { inclusive = true } }
                },
                onNeedsLogin = {
                    navController.navigate(IFoxyRoutes.LOGIN) { popUpTo(IFoxyRoutes.SPLASH) { inclusive = true } }
                },
            )
        }
        composable(IFoxyRoutes.LOGIN) {
            LoginScreen(
                authRepository = app.authRepository,
                onSignedIn = {
                    app.accountStore.activeAccount()?.let { app.accountSwitcher.activate(it.id) }
                    navController.navigate(IFoxyRoutes.HOME) { popUpTo(IFoxyRoutes.LOGIN) { inclusive = true } }
                },
            )
        }
        composable(IFoxyRoutes.ADD_ACCOUNT) {
            LoginScreen(
                authRepository = app.authRepository,
                onSignedIn = {
                    // The completed login filed itself in the vault and
                    // became the active account; sync the UI caches and
                    // re-dial the tunnel on it if one is running.
                    app.accountStore.activeAccount()?.let { app.accountSwitcher.activate(it.id) }
                    navScope.launch { app.accountSwitcher.restartTunnelIfRunning() }
                    navController.popBackStack()
                },
            )
        }
        composable(IFoxyRoutes.HOME) {
            HomeScreen(
                app = app,
                themeController = themeController,
                onRequestConnect = onRequestConnect,
                onDisconnect = onDisconnect,
                onOpenServers = { navController.navigate(IFoxyRoutes.SERVERS) },
                onOpenSettings = { navController.navigate(IFoxyRoutes.SETTINGS) },
            )
        }
        composable(IFoxyRoutes.SERVERS) {
            ServerListScreen(
                serverListClient = app.serverListClient,
                proxyStateStore = app.proxyStateStore,
                onServerSelected = { navController.popBackStack() },
                onBack = { navController.popBackStack() },
            )
        }
        composable(IFoxyRoutes.SETTINGS) {
            SettingsScreen(
                settingsStore = app.settingsStore,
                darkTheme = themeController.resolveDark(isSystemInDarkTheme()),
                updateController = updateController,
                accountStore = app.accountStore,
                onSwitchAccount = { id ->
                    app.accountSwitcher.activate(id)
                    navScope.launch { app.accountSwitcher.restartTunnelIfRunning() }
                },
                onRemoveAccount = { id ->
                    if (id == app.accountStore.activeAccountId) {
                        signOutActiveAccount()
                    } else {
                        app.accountStore.remove(id)
                    }
                },
                onAddAccount = { navController.navigate(IFoxyRoutes.ADD_ACCOUNT) },
                onOpenLogs = { navController.navigate(IFoxyRoutes.LOGS) },
                onSignOut = { signOutActiveAccount() },
                onBack = { navController.popBackStack() },
            )
        }
        composable(IFoxyRoutes.LOGS) {
            LogsScreen(onBack = { navController.popBackStack() })
        }
    }
    AppUpdateDialog(updateController)
    }
}
