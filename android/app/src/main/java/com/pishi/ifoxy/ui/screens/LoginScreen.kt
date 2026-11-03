package com.pishi.ifoxy.ui.screens

import android.app.Activity
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.PowerSettingsNew
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.view.WindowCompat
import com.pishi.ifoxy.data.FxaAuthRepository
import com.pishi.ifoxy.data.isUnconfirmedSession
import com.pishi.ifoxy.ui.components.WorldMapLayer
import com.pishi.ifoxy.ui.theme.IFoxyBgDark
import com.pishi.ifoxy.ui.theme.IFoxyErrorOnDark
import com.pishi.ifoxy.ui.theme.IFoxyInk
import com.pishi.ifoxy.ui.theme.IFoxyNeonOrange
import com.pishi.ifoxy.ui.theme.IFoxyYellow
import com.pishi.ifoxy.ui.theme.PoppinsFamily
import kotlinx.coroutines.launch
import org.json.JSONObject

/**
 * Sign in, per the Penpot design (04): dark brand screen, glowing orange
 * power mark. The credential form is gone: sign-in itself happens on
 * Mozilla's official Firefox Accounts page, shown inside the app by
 * [BrowserLoginScreen]. The direct API login this screen used to drive
 * is blocked by Mozilla's bot protection (HTTP 406), and with the page
 * flow the password and any verification code are entered on Mozilla's
 * page and never pass through this app's own code. The page hands the
 * app a session token via the FxA WebChannel protocol, and
 * [FxaAuthRepository.completeBrowserLogin] exchanges it for the usual
 * OAuth tokens.
 */
@Composable
fun LoginScreen(
    authRepository: FxaAuthRepository,
    onSignedIn: () -> Unit,
    onOpenSettings: () -> Unit = {},
    onOpenLogs: () -> Unit = {},
) {
    var browserStartUrl by rememberSaveable { mutableStateOf<String?>(null) }
    var completingBrowserLogin by rememberSaveable { mutableStateOf(false) }
    var errorMessage by rememberSaveable { mutableStateOf<String?>(null) }
    var infoMessage by rememberSaveable { mutableStateOf<String?>(null) }
    val scope = rememberCoroutineScope()

    fun handleBrowserSession(sessionToken: String, preExchangedToken: JSONObject?) {
        if (completingBrowserLogin) return
        completingBrowserLogin = true
        errorMessage = null
        infoMessage = null
        scope.launch {
            val result = authRepository.completeBrowserLogin(sessionToken, preExchangedToken)
            completingBrowserLogin = false
            result.onSuccess {
                browserStartUrl = null
                onSignedIn()
            }.onFailure {
                if (it.isUnconfirmedSession()) {
                    // Mozilla accepted the credentials but still wants
                    // the sign-in confirmed from the email it sent; the
                    // session cannot be exchanged until that happens.
                    browserStartUrl = null
                    infoMessage =
                        "Mozilla is waiting for you to confirm this sign-in from the " +
                            "email it sent you. Confirm it, then sign in again."
                } else {
                    errorMessage = it.message ?: "Sign-in failed. Please try again."
                }
            }
        }
    }

    if (browserStartUrl != null) {
        BrowserLoginScreen(
            startUrl = browserStartUrl!!,
            busy = completingBrowserLogin,
            errorMessage = errorMessage,
            onSessionCaptured = ::handleBrowserSession,
            onCanceled = {
                browserStartUrl = null
                completingBrowserLogin = false
                errorMessage = null
            },
            onOpenLogs = onOpenLogs,
            exchangeToken = { token, webView, bridge ->
                runTokenExchangeInPage(
                    webView,
                    bridge,
                    authRepository.buildBrowserTokenRequest(token),
                )
            },
        )
        return
    }

    // This screen is always drawn on the dark brand background, but the
    // theme derives status-bar icon appearance from the app theme: in
    // the light theme it picks dark icons, which vanish on this dark
    // surface. Force light icons while composed and hand back the
    // theme-driven value (captured before overriding) on dispose.
    val view = LocalView.current
    DisposableEffect(view) {
        val controller = (view.context as? Activity)?.window
            ?.let { WindowCompat.getInsetsController(it, view) }
        val themeDrivenAppearance = controller?.isAppearanceLightStatusBars
        controller?.isAppearanceLightStatusBars = false
        onDispose {
            if (themeDrivenAppearance != null) {
                controller?.isAppearanceLightStatusBars = themeDrivenAppearance
            }
        }
    }

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(IFoxyBgDark)
            .imePadding(),
        contentAlignment = Alignment.TopCenter,
    ) {
        // Faint static world map behind the header (design 04).
        WorldMapLayer(
            color = Color.White.copy(alpha = 0.045f),
            driftMillis = null,
            modifier = Modifier
                .fillMaxWidth()
                .height(360.dp),
        )

        Column(
            modifier = Modifier
                .widthIn(max = 520.dp)
                .fillMaxWidth()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 24.dp),
            verticalArrangement = Arrangement.Top,
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Spacer(Modifier.height(72.dp))

            // Glowing orange power mark.
            Box(contentAlignment = Alignment.Center) {
                Box(
                    modifier = Modifier
                        .size(120.dp)
                        .clip(CircleShape)
                        .background(
                            Brush.radialGradient(
                                colors = listOf(
                                    IFoxyNeonOrange.copy(alpha = 0.4f),
                                    IFoxyNeonOrange.copy(alpha = 0f),
                                ),
                            ),
                        ),
                )
                Box(
                    modifier = Modifier
                        .size(72.dp)
                        .clip(CircleShape)
                        .background(IFoxyNeonOrange),
                    contentAlignment = Alignment.Center,
                ) {
                    Icon(
                        imageVector = Icons.Filled.PowerSettingsNew,
                        contentDescription = null,
                        tint = Color.White,
                        modifier = Modifier.size(36.dp),
                    )
                }
            }

            Spacer(Modifier.height(22.dp))
            Text(
                "Welcome to iFoxy",
                style = TextStyle(
                    fontFamily = PoppinsFamily,
                    fontWeight = FontWeight.Bold,
                    fontSize = 24.sp,
                ),
                color = Color.White,
            )
            Spacer(Modifier.height(6.dp))
            Text(
                "Sign in with your Firefox account",
                style = TextStyle(
                    fontFamily = PoppinsFamily,
                    fontWeight = FontWeight.Normal,
                    fontSize = 14.sp,
                ),
                color = Color.White.copy(alpha = 0.6f),
            )
            Spacer(Modifier.height(30.dp))

            Text(
                "Sign-in opens Mozilla's official Firefox page inside the app. " +
                    "Your password is entered there — iFoxy never sees or stores it.",
                style = TextStyle(
                    fontFamily = PoppinsFamily,
                    fontWeight = FontWeight.Normal,
                    fontSize = 13.5.sp,
                ),
                color = Color.White.copy(alpha = 0.65f),
                textAlign = TextAlign.Center,
                modifier = Modifier.fillMaxWidth(),
            )
            Spacer(Modifier.height(20.dp))
            Button(
                onClick = {
                    errorMessage = null
                    infoMessage = null
                    browserStartUrl = authRepository.getBrowserLoginUrl()
                },
                colors = ButtonDefaults.buttonColors(
                    containerColor = IFoxyYellow,
                    contentColor = IFoxyInk,
                ),
                shape = RoundedCornerShape(27.dp),
                modifier = Modifier
                    .fillMaxWidth()
                    .height(54.dp),
            ) {
                Text(
                    "Sign In",
                    style = TextStyle(
                        fontFamily = PoppinsFamily,
                        fontWeight = FontWeight.SemiBold,
                        fontSize = 15.5.sp,
                    ),
                )
            }

            infoMessage?.let {
                Spacer(Modifier.height(14.dp))
                Text(
                    text = it,
                    color = IFoxyYellow,
                    textAlign = TextAlign.Center,
                    style = TextStyle(
                        fontFamily = PoppinsFamily,
                        fontWeight = FontWeight.Medium,
                        fontSize = 13.sp,
                    ),
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 8.dp)
                        .semantics { liveRegion = LiveRegionMode.Polite },
                )
            }
            errorMessage?.let {
                Spacer(Modifier.height(14.dp))
                Text(
                    text = it,
                    color = IFoxyErrorOnDark,
                    textAlign = TextAlign.Center,
                    style = TextStyle(
                        fontFamily = PoppinsFamily,
                        fontWeight = FontWeight.Medium,
                        fontSize = 13.sp,
                    ),
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 8.dp)
                        .semantics { liveRegion = LiveRegionMode.Polite },
                )
            }
            Spacer(Modifier.height(18.dp))
            Text(
                "Two-factor authentication is supported — Mozilla's page asks for the code itself",
                style = TextStyle(
                    fontFamily = PoppinsFamily,
                    fontWeight = FontWeight.Normal,
                    fontSize = 12.sp,
                ),
                color = Color.White.copy(alpha = 0.65f),
                textAlign = TextAlign.Center,
            )
            Spacer(Modifier.height(6.dp))
            Text(
                "Firefox accounts that sign in with Google or Apple cannot be used on the in-app page",
                style = TextStyle(
                    fontFamily = PoppinsFamily,
                    fontWeight = FontWeight.Normal,
                    fontSize = 12.sp,
                ),
                color = Color.White.copy(alpha = 0.65f),
                textAlign = TextAlign.Center,
            )
            Spacer(Modifier.height(26.dp))
            // The sign-in gate must not lock the user out of the rest of
            // the app: Settings and Logs stay reachable while signed out
            // (support and diagnostics depend on them exactly when
            // sign-in itself is broken).
            Row(
                horizontalArrangement = Arrangement.Center,
                modifier = Modifier.fillMaxWidth(),
            ) {
                TextButton(onClick = onOpenSettings) {
                    Text(
                        "Settings",
                        color = Color.White.copy(alpha = 0.65f),
                        style = TextStyle(
                            fontFamily = PoppinsFamily,
                            fontWeight = FontWeight.Medium,
                            fontSize = 13.sp,
                        ),
                    )
                }
                TextButton(onClick = onOpenLogs) {
                    Text(
                        "Logs",
                        color = Color.White.copy(alpha = 0.65f),
                        style = TextStyle(
                            fontFamily = PoppinsFamily,
                            fontWeight = FontWeight.Medium,
                            fontSize = 13.sp,
                        ),
                    )
                }
            }
            Spacer(Modifier.height(32.dp))
        }
    }
}
