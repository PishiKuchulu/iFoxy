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
import androidx.compose.runtime.key
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
import com.pishi.ifoxy.data.AppLogger
import com.pishi.ifoxy.data.FxaAuthRepository
import com.pishi.ifoxy.data.isCaptchaChallenge
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

/** What [LoginScreen] does with an "Unconfirmed session" verdict
 *  (FxA errno 104) from the native token exchange. Pure, so the
 *  waiting mode's retry discipline is unit-testable. */
internal enum class UnconfirmedFailureAction {
    /** First unconfirmed verdict for a session: keep the browser
     *  open in the waiting-for-confirmation mode (v1.0.38). */
    ENTER_WAITING_MODE,

    /** The waiting mode's MANUAL retry still came back
     *  unconfirmed: manual attempts are the user's own call, so
     *  the mode stays up and they can finish entering the code
     *  and tap Continue again. */
    STAY_IN_WAITING_MODE,

    /** The waiting mode's one AUTOMATIC retry still came back
     *  unconfirmed: fall back to the terminal behavior (close the
     *  browser, "confirm from the email, then sign in again")
     *  instead of looping. */
    TERMINAL_FALLBACK,
}

internal fun unconfirmedFailureAction(
    wasWaitingModeRetry: Boolean,
    retryWasManual: Boolean,
): UnconfirmedFailureAction = when {
    !wasWaitingModeRetry -> UnconfirmedFailureAction.ENTER_WAITING_MODE
    retryWasManual -> UnconfirmedFailureAction.STAY_IN_WAITING_MODE
    else -> UnconfirmedFailureAction.TERMINAL_FALLBACK
}

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
    // Manual Fastly verification (v1.0.36): the session token whose
    // native exchange died on an interactive CAPTCHA, and whether
    // its one manual-verification retry has already been spent (a
    // second CAPTCHA failure surfaces the error instead of looping
    // back into the challenge step).
    var captchaSessionToken by rememberSaveable { mutableStateOf<String?>(null) }
    var captchaRetryUsed by rememberSaveable { mutableStateOf(false) }
    // Email confirmation wait (v1.0.38): the session token whose
    // native exchange FxA refused with errno 104 "Unconfirmed
    // session" — Mozilla emailed a confirmation code and the
    // session cannot be exchanged until the code is entered on
    // Mozilla's page. The browser screen stays composed in a
    // waiting mode (see unconfirmedFailureAction) instead of being
    // torn down: nulling the start URL used to destroy the WebView,
    // the only surface where the code could ever be typed, and
    // left the emailed code with nowhere to go.
    // unconfirmedRetryUsed spends the mode's single AUTOMATIC
    // retry; manual Continue taps are the user's own call and may
    // re-attempt.
    var unconfirmedSessionToken by rememberSaveable { mutableStateOf<String?>(null) }
    var unconfirmedRetryUsed by rememberSaveable { mutableStateOf(false) }
    val scope = rememberCoroutineScope()

    fun handleBrowserSession(
        sessionToken: String,
        preExchangedToken: JSONObject?,
        unconfirmedRetry: Boolean = false,
        unconfirmedManual: Boolean = false,
    ) {
        if (completingBrowserLogin) return
        completingBrowserLogin = true
        errorMessage = null
        infoMessage = null
        scope.launch {
            val result = authRepository.completeBrowserLogin(sessionToken, preExchangedToken)
            completingBrowserLogin = false
            result.onSuccess {
                captchaSessionToken = null
                unconfirmedSessionToken = null
                unconfirmedRetryUsed = false
                browserStartUrl = null
                onSignedIn()
            }.onFailure {
                if (it.isCaptchaChallenge() && !captchaRetryUsed) {
                    // Mozilla's bot protection demands an interactive
                    // CAPTCHA — the one challenge no native code can
                    // answer. Instead of the dead-end error, offer
                    // the manual verification step: the user passes
                    // the check on Mozilla's page in the WebView, its
                    // cookies are harvested into the native jar, and
                    // this same session token gets exactly one native
                    // retry (see onChallengePassed below).
                    AppLogger.i(
                        "LoginScreen",
                        "CAPTCHA verdict on the native token exchange; presenting the " +
                            "manual verification step (browser-earned cookies are " +
                            "harvested into the native jar before the single retry)",
                    )
                    captchaRetryUsed = true
                    unconfirmedSessionToken = null
                    unconfirmedRetryUsed = false
                    captchaSessionToken = sessionToken
                } else if (it.isUnconfirmedSession()) {
                    when (unconfirmedFailureAction(unconfirmedRetry, unconfirmedManual)) {
                        UnconfirmedFailureAction.ENTER_WAITING_MODE -> {
                            // Mozilla accepted the credentials but
                            // still wants the sign-in confirmed with
                            // the code it emailed. Do NOT tear the
                            // browser down (the pre-1.0.38 behavior:
                            // the WebView is destroyed and the code
                            // has nowhere to be typed). Keep the
                            // token and put the browser into the
                            // waiting mode instead: the page-side
                            // verify hooks — or the user's Continue
                            // tap — retry this same token once the
                            // session is confirmed on Mozilla's page.
                            AppLogger.i(
                                "LoginScreen",
                                "Unconfirmed-session verdict on the native token exchange; " +
                                    "keeping the browser open on Mozilla's page so the " +
                                    "emailed confirmation code can be entered there",
                            )
                            unconfirmedRetryUsed = false
                            unconfirmedSessionToken = sessionToken
                        }
                        UnconfirmedFailureAction.STAY_IN_WAITING_MODE -> {
                            // A manual retry the user asked for while
                            // still confirming: stay in the mode so
                            // they can finish entering the code and
                            // tap Continue again.
                            errorMessage =
                                "Mozilla still shows this sign-in as unconfirmed. " +
                                    "Enter the code from the email on the page below, " +
                                    "then tap Continue."
                        }
                        UnconfirmedFailureAction.TERMINAL_FALLBACK -> {
                            // The mode's one automatic retry also
                            // came back unconfirmed: the previous
                            // terminal behavior, never a loop.
                            unconfirmedSessionToken = null
                            unconfirmedRetryUsed = false
                            browserStartUrl = null
                            infoMessage =
                                "Mozilla is waiting for you to confirm this sign-in from the " +
                                    "email it sent you. Confirm it, then sign in again."
                        }
                    }
                } else {
                    errorMessage = it.message ?: "Sign-in failed. Please try again."
                }
            }
        }
    }

    // The browser screen composes while a sign-in page is open OR
    // while a manual-verification challenge is pending OR while an
    // email confirmation is pending. The extra disjuncts matter
    // (v1.0.37): a mid-exchange "Cancel and try again" tap can null
    // browserStartUrl before the native exchange's CAPTCHA verdict
    // lands; gating on browserStartUrl alone then swallowed the
    // verdict — captchaSessionToken was set but the challenge step
    // never composed and no message showed. A pending step token
    // must present on its own.
    if (browserStartUrl != null || captchaSessionToken != null || unconfirmedSessionToken != null) {
        val challengeToken = captchaSessionToken
        val unconfirmedToken = unconfirmedSessionToken
        // Keyed on the mode: entering or leaving a step rebuilds
        // the screen with a fresh WebView (the factory loads
        // startUrl only once) — the verification step pointed at
        // the Firefox host that serves the challenge, and the
        // confirmation wait pointed back at the sign-in start URL
        // (the clearance flow may have navigated the previous
        // WebView to the API host, where no code form exists).
        key(
            when {
                challengeToken != null -> 1
                unconfirmedToken != null -> 2
                else -> 0
            },
        ) {
            BrowserLoginScreen(
                startUrl = when {
                    challengeToken != null -> "https://accounts.firefox.com/"
                    // The sign-in start URL: Mozilla's page routes
                    // the unconfirmed session to its code form from
                    // there, even if the clearance flow left the
                    // previous WebView sitting on the API host.
                    unconfirmedToken != null -> authRepository.getBrowserLoginUrl()
                    else -> browserStartUrl!!
                },
                busy = completingBrowserLogin,
                errorMessage = errorMessage,
                onSessionCaptured = ::handleBrowserSession,
                onCanceled = {
                    // Cancel semantics (v1.0.37): while a captured
                    // session's native completion is in flight, its
                    // success / CAPTCHA / error verdict is still
                    // going to land here — clearing the browser /
                    // challenge state now would swallow that verdict
                    // (the 1.0.36 on-device failure: the challenge
                    // step never appeared after a mid-exchange
                    // cancel). In that case the cancel only leaves
                    // the WebView interactive again; the completion
                    // owns the state until it finishes. A cancel
                    // with nothing in flight is a plain abandon and
                    // clears everything, as before.
                    if (!completingBrowserLogin) {
                        browserStartUrl = null
                        errorMessage = null
                        captchaSessionToken = null
                        captchaRetryUsed = false
                        unconfirmedSessionToken = null
                        unconfirmedRetryUsed = false
                    }
                },
                onOpenLogs = onOpenLogs,
                challengeToken = challengeToken,
                onChallengePassed = {
                    val token = captchaSessionToken
                    captchaSessionToken = null
                    if (token != null) {
                        scope.launch {
                            // Move whatever clearance the browser
                            // earned during the manual check into the
                            // native jar BEFORE the one retry, so the
                            // exchange carries it (the v1.0.35 logs
                            // show exactly what the retry sends).
                            runCatching { authRepository.harvestWebViewCookies() }
                                .onFailure {
                                    AppLogger.w("LoginScreen", "WebView cookie harvest failed", it)
                                }
                            handleBrowserSession(token, null)
                        }
                    }
                },
                unconfirmedToken = unconfirmedToken,
                onConfirmationPassed = { manual ->
                    val token = unconfirmedSessionToken
                    if (token != null && !completingBrowserLogin) {
                        // The mode gets exactly one AUTOMATIC retry
                        // per entry: page-side signals after that
                        // budget is spent are ignored, and the spent
                        // retry's own verdict decides what happens
                        // (see unconfirmedFailureAction). Manual
                        // Continue taps always re-attempt.
                        val autoBudgetSpent = !manual && unconfirmedRetryUsed
                        if (!autoBudgetSpent) {
                            if (!manual) unconfirmedRetryUsed = true
                            handleBrowserSession(
                                token,
                                null,
                                unconfirmedRetry = true,
                                unconfirmedManual = manual,
                            )
                        }
                    }
                },
                exchangeToken = { token, webView, bridge ->
                    runTokenExchangeWithClearance(
                        webView,
                        bridge,
                        authRepository.buildBrowserTokenRequest(token),
                    )
                },
            )
        }
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
                    captchaSessionToken = null
                    captchaRetryUsed = false
                    unconfirmedSessionToken = null
                    unconfirmedRetryUsed = false
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
