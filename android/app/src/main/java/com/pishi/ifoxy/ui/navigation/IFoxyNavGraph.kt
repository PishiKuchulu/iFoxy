package com.pishi.ifoxy.ui.navigation

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
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
    LaunchedEffect(Unit) { updateController.checkOnLaunch() }
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
                    navController.navigate(IFoxyRoutes.HOME) { popUpTo(IFoxyRoutes.LOGIN) { inclusive = true } }
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
                onOpenLogs = { navController.navigate(IFoxyRoutes.LOGS) },
                onSignOut = {
                    onDisconnect()
                    app.tokenStore.clear()
                    app.settingsStore.clearAccountSession()
                    app.proxyStateStore.clear()
                    navController.navigate(IFoxyRoutes.LOGIN) { popUpTo(0) { inclusive = true } }
                },
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
