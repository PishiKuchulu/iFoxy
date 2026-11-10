package com.pishi.ifoxy.ui.screens

import android.annotation.SuppressLint
import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.webkit.CookieManager
import android.webkit.JavascriptInterface
import android.webkit.WebChromeClient
import android.webkit.WebResourceError
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.view.WindowCompat
import com.pishi.ifoxy.data.AppLogger
import com.pishi.ifoxy.data.BrowserTokenRequest
import com.pishi.ifoxy.data.FIREFOX_ANDROID_UA
import com.pishi.ifoxy.ui.theme.IFoxyBgDark
import com.pishi.ifoxy.ui.theme.IFoxyErrorOnDark
import com.pishi.ifoxy.ui.theme.IFoxyYellow
import com.pishi.ifoxy.ui.theme.PoppinsFamily
import java.lang.ref.WeakReference
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.coroutines.resume
import org.json.JSONObject

private const val TAG = "BrowserLogin"

private const val FXA_CHANNEL_ID = "account_updates"
private const val CMD_FXA_STATUS = "fxaccounts:fxa_status"
private const val CMD_CAN_LINK_ACCOUNT = "fxaccounts:can_link_account"
private const val CMD_LOGIN = "fxaccounts:login"

private val SESSION_TOKEN_HEX = Regex("^[0-9a-f]{64}$")

private fun jsString(value: String): String = JSONObject.quote(value)

private val WEBCHANNEL_HOOK_JS = """
(function() {
  if (window.__foxyChannelHooked) return;
  window.__foxyChannelHooked = true;
  var forward = function (detail) {
    try {
      var host = window.location.hostname;
      if (host !== 'accounts.firefox.com' && !host.endsWith('.firefox.com')) return;
      var payload = typeof detail === 'string' ? detail : JSON.stringify(detail);
      foxyWebChannel.onMessage(payload, window.location.href);
    } catch (e) {}
  };
  window.addEventListener('WebChannelMessageToChrome', function (e) { forward(e.detail); });
  document.addEventListener('WebChannelMessageToChrome', function (e) { forward(e.detail); });
  window.__foxyReply = function (channelId, messageId, command, dataJson) {
    try {
      var parsedData = typeof dataJson === 'string' ? JSON.parse(dataJson) : dataJson;
      var envelope = {
        id: channelId,
        message: { messageId: messageId, command: command, data: parsedData }
      };
      var eventObj = new CustomEvent('WebChannelMessageToContent', { detail: envelope });
      window.dispatchEvent(eventObj);
      document.dispatchEvent(eventObj);
      var eventStr = new CustomEvent('WebChannelMessageToContent', { detail: JSON.stringify(envelope) });
      window.dispatchEvent(eventStr);
      document.dispatchEvent(eventStr);
    } catch (e) {}
  };
  var getUrlString = function(arg) {
    if (!arg) return '';
    if (typeof arg === 'string') return arg;
    if (typeof arg.url === 'string') return arg.url;
    if (typeof arg.href === 'string') return arg.href;
    try { return arg.toString(); } catch (e) { return ''; }
  };
  var checkVerifyUrl = function(url) {
    var u = getUrlString(url).toLowerCase();
    return u.indexOf('/verify') !== -1 || u.indexOf('/totp') !== -1 || u.indexOf('/session/verify') !== -1;
  };
  var checkSuccessUrl = function(url) {
    var u = getUrlString(url).toLowerCase();
    return u.indexOf('/signin/confirmed') !== -1 || u.indexOf('/connect_another_device') !== -1 ||
           u.indexOf('/pair') !== -1 || u.indexOf('/complete') !== -1;
  };
  if (window.fetch) {
    var origFetch = window.fetch;
    window.fetch = function() {
      var reqUrl = (arguments[0] && arguments[0].url) || arguments[0] || '';
      return origFetch.apply(this, arguments).then(function(res) {
        try {
          if (res && res.ok && checkVerifyUrl(reqUrl)) {
            foxyWebChannel.onSessionVerified();
          }
        } catch (e) {}
        return res;
      });
    };
  }
  if (window.XMLHttpRequest) {
    var origOpen = XMLHttpRequest.prototype.open;
    var origSend = XMLHttpRequest.prototype.send;
    XMLHttpRequest.prototype.open = function(method, url) {
      this.__foxyReqUrl = url;
      return origOpen.apply(this, arguments);
    };
    XMLHttpRequest.prototype.send = function() {
      this.addEventListener('load', function() {
        try {
          if (this.status >= 200 && this.status < 300 && checkVerifyUrl(this.__foxyReqUrl)) {
            foxyWebChannel.onSessionVerified();
          }
        } catch (e) {}
      });
      return origSend.apply(this, arguments);
    };
  }
  var notifyNav = function() {
    try {
      if (checkSuccessUrl(window.location.href)) {
        foxyWebChannel.onSessionVerified();
      }
    } catch (e) {}
  };
  var origPushState = history.pushState;
  if (origPushState) {
    history.pushState = function() {
      var ret = origPushState.apply(this, arguments);
      notifyNav();
      return ret;
    };
  }
  var origReplaceState = history.replaceState;
  if (origReplaceState) {
    history.replaceState = function() {
      var ret = origReplaceState.apply(this, arguments);
      notifyNav();
      return ret;
    };
  }
  window.addEventListener('popstate', notifyNav);
  window.addEventListener('hashchange', notifyNav);
})();
""".trimIndent()

/**
 * Bridge between the FxA web page and the app. The page talks to its
 * embedding "browser" through WebChannel messages; the injected hook
 * script forwards them here, and the two-argument [onMessage] drops
 * messages whose caller-supplied origin URL is not a firefox.com host.
 *
 * Security invariant, stated honestly: a JavascriptInterface cannot
 * authenticate WHICH frame invoked it, and the origin string checked
 * here is supplied by the page itself, so bridge calls must be treated
 * as unauthenticated by frame. The real protection is that the only
 * value taken from the page is the session token, accepted solely in
 * its canonical 64-hex shape: the token is a bearer secret that a
 * caller must already possess (it cannot be extracted or forged), and
 * it is released to the app only once the session is verified (the
 * page completes any email-code / TOTP step itself first). There is
 * deliberately no convenience overload that defaults or hard-codes a
 * trusted origin.
 *
 * Kept whole by proguard-rules.pro: the WebView reaches these methods
 * reflectively through the JavascriptInterface name.
 */
internal class WebChannelBridge(
    webView: WebView,
    private val onSessionToken: (String) -> Unit,
) {
    private val webViewRef = WeakReference(webView)
    @Volatile
    var pendingSessionToken: String? = null
        private set

    /** True while the token parked here is still UNVERIFIED —
     *  the page has not completed its own confirmation step
     *  (email code / TOTP) for it yet, so the session is awaiting
     *  page-side confirmation. The clearance flow consults this
     *  before navigating the WebView to the API host: replacing
     *  the page while it holds an unconfirmed session would
     *  destroy the only surface where the user can finish
     *  confirming it. Cleared whenever a token is released. */
    @Volatile
    var hasUnverifiedParkedSession: Boolean = false
        private set

    @JavascriptInterface
    fun onSessionVerified() {
        val token = pendingSessionToken ?: return
        notifySessionToken(token)
    }

    /** One-shot receiver for the in-page token exchange (see
     *  runTokenExchangeInPage). Armed only while an exchange the app
     *  itself started is in flight; the payload is validated as an
     *  FxA token response before it is used. */
    @Volatile
    var tokenExchangeCallback: ((String) -> Unit)? = null

    @JavascriptInterface
    fun onTokenExchangeResult(payload: String) {
        val callback = tokenExchangeCallback
        tokenExchangeCallback = null
        callback?.invoke(payload)
    }

    @JavascriptInterface
    fun onMessage(payload: String, originUrl: String) {
        val host = runCatching { Uri.parse(originUrl).host?.lowercase() }.getOrNull()
        if (host != "accounts.firefox.com" && host?.endsWith(".firefox.com") != true) {
            return
        }
        val message = runCatching {
            JSONObject(payload).optJSONObject("message") ?: JSONObject()
        }.getOrNull() ?: return
        val command = message.optString("command")
        val data = message.optJSONObject("data") ?: JSONObject()
        val messageId = message.optString("messageId")

        when (command) {
            CMD_FXA_STATUS -> reply(
                messageId,
                CMD_FXA_STATUS,
                """{"capabilities":{},"signedInUser":null}""",
            )
            CMD_CAN_LINK_ACCOUNT -> reply(
                messageId,
                CMD_CAN_LINK_ACCOUNT,
                """{"ok":true}""",
            )
            CMD_LOGIN, "fxaccounts:oauth_login" -> {
                val token = data.optString("sessionToken", "").trim()
                    .ifBlank { data.optString("token", "").trim() }
                if (SESSION_TOKEN_HEX.matches(token)) {
                    pendingSessionToken = token
                    // A missing "verified" field means UNVERIFIED:
                    // the token stays pending until the page proves
                    // the session (verify/TOTP completion hooks).
                    val isVerified = data.optBoolean("verified", false)
                    hasUnverifiedParkedSession = !isVerified
                    if (isVerified) {
                        notifySessionToken(token)
                    }
                }
                if (messageId.isNotBlank()) {
                    reply(messageId, command, """{"ok":true}""")
                }
            }
            else -> {
                if (command.contains("verified", ignoreCase = true)) {
                    val token = data.optString("sessionToken", "").trim()
                        .ifBlank { data.optString("token", "").trim() }
                        .ifBlank { pendingSessionToken ?: "" }
                    if (SESSION_TOKEN_HEX.matches(token)) {
                        pendingSessionToken = token
                        notifySessionToken(token)
                    }
                }
                if (messageId.isNotBlank()) {
                    reply(messageId, command, """{"ok":true}""")
                }
            }
        }
    }

    fun notifySessionToken(token: String) {
        if (!SESSION_TOKEN_HEX.matches(token)) return
        hasUnverifiedParkedSession = false
        val view = webViewRef.get()
        if (view != null) {
            view.post { onSessionToken(token) }
        } else {
            onSessionToken(token)
        }
    }

    private fun reply(messageId: String, command: String, dataJson: String) {
        val view = webViewRef.get() ?: return
        val script = "window.__foxyReply && window.__foxyReply(" +
            "${jsString(FXA_CHANNEL_ID)}, ${jsString(messageId)}, ${jsString(command)}, ${jsString(dataJson)});"
        view.post {
            runCatching { view.evaluateJavascript(script, null) }
                .onFailure { AppLogger.w(TAG, "could not answer webchannel command $command", it) }
        }
    }
}

private fun isSuccessUrl(url: String?): Boolean {
    if (url.isNullOrBlank()) return false
    val u = url.lowercase()
    return u.contains("/signin/confirmed") ||
        u.contains("/connect_another_device") ||
        u.contains("/pair") ||
        u.contains("/complete")
}

/**
 * Mozilla's official Firefox Accounts sign-in page, embedded in the
 * app. The user signs in on Mozilla's page itself (password and any
 * verification code are entered there and never pass through this
 * app's own code); when the page reports a verified session through
 * WebChannel, [onSessionCaptured] receives the session token.
 */
@SuppressLint("SetJavaScriptEnabled")
/** Executes a Hawk-signed FxA token request inside the signed-in page
 *  itself: the browser's network stack already passed Mozilla's bot
 *  protection, so the exchange rides that trust instead of fighting
 *  the native client's HTTP 406. Returns the parsed token response on
 *  HTTP 200, or null on any failure (the caller falls back to the
 *  native exchange). */
internal class InPageExchangeOutcome(
    val tokenJson: JSONObject?,
    /** HTTP status of the exchange fetch; -1 when it never answered. */
    val status: Int,
    /** The response looks like a bot-protection block rather than an
     *  FxA answer (see [isBlockedLikeExchange]). */
    val blockedLike: Boolean,
)

/** Whether an in-page exchange response is Mozilla's bot protection
 *  rather than FxA itself answering: HTTP 406, or an HTTP 200 whose
 *  body is not the token JSON (a challenge interstitial page served
 *  to the fetch in place of the API answer). */
internal fun isBlockedLikeExchange(status: Int, hasTokenJson: Boolean): Boolean =
    status == 406 || (status == 200 && !hasTokenJson)

/** Whether an exchange outcome ends the clearance flow in
 *  [runTokenExchangeWithClearance]. Only a REAL FxA answer is
 *  terminal: an HTTP response was received (status > 0) and it is
 *  not block-like — FxA has spoken, and more recovery cannot change
 *  its answer. A "no answer" outcome (status 0 when the fetch
 *  rejected, -1 when it never returned — the 2026-11-09 on-device
 *  log, where the cookie retry died with "TypeError: Failed to
 *  fetch") says nothing about FxA: classifying it as terminal used
 *  to abort the flow BEFORE the WebView-navigation clearance step,
 *  so sign-in fell back to the native exchange and its dead end.
 *  The poll loop in the clearance flow uses this same rule. */
internal fun isTerminalExchangeOutcome(outcome: InPageExchangeOutcome): Boolean =
    !outcome.blockedLike && outcome.status > 0

/** The scheme://host[:port]/ origin of a URL, or null when it does
 *  not parse into one. Used to open the FxA API host itself in the
 *  browser so its own pages can clear the bot-protection challenge. */
internal fun apiOriginOf(url: String): String? {
    val uri = runCatching { java.net.URI(url) }.getOrNull() ?: return null
    val scheme = uri.scheme ?: return null
    val host = uri.host ?: return null
    return if (uri.port > 0) "$scheme://$host:${uri.port}/" else "$scheme://$host/"
}

internal suspend fun runTokenExchangeInPage(
    webView: WebView,
    bridge: WebChannelBridge,
    spec: BrowserTokenRequest,
    credentialsMode: String = "omit",
    timeoutMs: Long = 25_000,
): InPageExchangeOutcome {
    val payload = withTimeoutOrNull(timeoutMs) {
        suspendCancellableCoroutine<String> { cont ->
            bridge.tokenExchangeCallback = { result ->
                if (cont.isActive) cont.resume(result)
            }
            cont.invokeOnCancellation { bridge.tokenExchangeCallback = null }
            val script = "(function(){try{fetch(" + JSONObject.quote(spec.url) +
                ",{method:'POST',headers:{'Content-Type':'application/json','Authorization':" +
                JSONObject.quote(spec.authorization) +
                "},body:" + JSONObject.quote(spec.bodyJson) +
                ",credentials:" + JSONObject.quote(credentialsMode) + "}).then(function(r){return r.text().then(function(t){" +
                "window.foxyWebChannel.onTokenExchangeResult(JSON.stringify({status:r.status,body:t}));});})" +
                ".catch(function(e){window.foxyWebChannel.onTokenExchangeResult(JSON.stringify({status:0,body:String(e)}));});" +
                "}catch(e){window.foxyWebChannel.onTokenExchangeResult(JSON.stringify({status:-1,body:String(e)}));}})();"
            webView.post { webView.evaluateJavascript(script, null) }
        }
    } ?: return InPageExchangeOutcome(null, -1, blockedLike = false)
    val outer = runCatching { JSONObject(payload) }.getOrNull()
        ?: return InPageExchangeOutcome(null, -1, blockedLike = false)
    val status = outer.optInt("status")
    if (status != 200) {
        AppLogger.w(
            "BrowserLoginScreen",
            "in-page token exchange failed: status=$status body=${outer.optString("body").take(200)}",
        )
        return InPageExchangeOutcome(null, status, isBlockedLikeExchange(status, hasTokenJson = false))
    }
    val tokenJson = runCatching { JSONObject(outer.optString("body")) }.getOrNull()
        ?.takeIf { it.optString("access_token").isNotBlank() }
    if (tokenJson != null) {
        AppLogger.i("BrowserLoginScreen", "in-page token exchange succeeded (HTTP 200)")
    }
    return InPageExchangeOutcome(tokenJson, status, isBlockedLikeExchange(status, tokenJson != null))
}

private const val CHALLENGE_CLEARANCE_DEADLINE_MS = 75_000L
private const val CHALLENGE_CLEARANCE_POLL_MS = 5_000L

/** How long the manual verification step (v1.0.36) watches the
 *  accounts page for the user to pass Mozilla's CAPTCHA before it
 *  stops auto-detecting; the Continue button remains after that. */
private const val MANUAL_CHALLENGE_TIMEOUT_MS = 180_000L

/** The in-page exchange with bot-protection recovery. On 2026-11-06
 *  the plain in-page fetch itself started returning HTTP 406 on a
 *  flagged network: the fetch sends no cookies and cannot execute
 *  Fastly's JavaScript challenge, so the trust the sign-in page
 *  earned does not carry to the API host. Recovery, in order:
 *  1. Retry the fetch WITH the browser's cookies (a domain-scoped
 *     clearance cookie from the sign-in pages may already exist).
 *  2. Open the API host itself in the WebView: a top-level browser
 *     navigation CAN run the challenge script, and the clearance
 *     cookie it earns is stored in the browser's own cookie jar.
 *     Then poll the exchange from that same-origin context (cookies
 *     included) until it answers or the deadline passes.
 *  Returns the token response, or null when every route is blocked
 *  (the caller then falls back to the native exchange, whose own
 *  failure message tells the user to switch networks). */
internal suspend fun runTokenExchangeWithClearance(
    webView: WebView,
    bridge: WebChannelBridge,
    spec: BrowserTokenRequest,
): JSONObject? {
    val first = runTokenExchangeInPage(webView, bridge, spec)
    if (first.tokenJson != null) return first.tokenJson
    if (isTerminalExchangeOutcome(first)) return null

    AppLogger.w(
        "BrowserLoginScreen",
        "in-page token exchange blocked (status=${first.status}); retrying with the browser's cookies",
    )
    val withCookies = runTokenExchangeInPage(
        webView,
        bridge,
        spec,
        credentialsMode = "include",
        timeoutMs = 15_000,
    )
    if (withCookies.tokenJson != null) return withCookies.tokenJson
    if (isTerminalExchangeOutcome(withCookies)) return null

    if (bridge.hasUnverifiedParkedSession) {
        // The page still holds an UNVERIFIED session token: it is
        // waiting for Mozilla's own confirmation step (email code
        // / TOTP) to be finished ON THAT PAGE. Navigating the
        // WebView to the API host would replace the page and
        // destroy the only place the code can be entered, so skip
        // the navigation recovery entirely (v1.0.38): the native
        // exchange's verdict — errno 104 for an unconfirmed
        // session — opens the waiting-for-confirmation mode on
        // the sign-in page instead.
        AppLogger.w(
            "BrowserLoginScreen",
            "skipping the API-host navigation: the page holds an " +
                "unverified session awaiting on-page confirmation",
        )
        return null
    }

    val apiOrigin = apiOriginOf(spec.url) ?: return null
    AppLogger.i(
        "BrowserLoginScreen",
        "opening $apiOrigin in the browser so it can clear the bot-protection challenge itself",
    )
    webView.post { webView.loadUrl(apiOrigin) }

    val deadline = System.currentTimeMillis() + CHALLENGE_CLEARANCE_DEADLINE_MS
    while (System.currentTimeMillis() < deadline) {
        delay(CHALLENGE_CLEARANCE_POLL_MS)
        val attempt = runTokenExchangeInPage(
            webView,
            bridge,
            spec,
            credentialsMode = "include",
            timeoutMs = 12_000,
        )
        if (attempt.tokenJson != null) return attempt.tokenJson
        if (isTerminalExchangeOutcome(attempt)) {
            // FxA itself answered (a rejection the native path will
            // report faithfully); more waiting cannot change it.
            AppLogger.w(
                "BrowserLoginScreen",
                "challenge clearance ended with an FxA answer: status=${attempt.status}",
            )
            return null
        }
        // status -1 (page still navigating / challenge running) or a
        // block-like response: keep waiting for the clearance cookie.
    }
    AppLogger.w("BrowserLoginScreen", "challenge clearance did not unblock the token exchange")
    return null
}

/** Whether the page currently shown in [webView] still looks like a
 *  Fastly client-challenge page, mirroring the markers the native
 *  solver's isChallengePage requires (an /_fs-ch- prefix plus one
 *  of the challenge markers). Used by the manual verification step
 *  (v1.0.36) to notice when the user has passed Mozilla's CAPTCHA:
 *  once the check passes, Fastly replaces the challenge page with
 *  the real Firefox page and the markers are gone. */
internal suspend fun webViewShowsFastlyChallenge(webView: WebView): Boolean {
    val script = "(function(){" +
        "var h=document.documentElement?document.documentElement.outerHTML:'';" +
        "if(h.indexOf('/_fs-ch-')===-1)return false;" +
        "var l=h.toLowerCase();" +
        "return l.indexOf('client challenge')!==-1||h.indexOf('fst-post-back')!==-1||" +
        "h.indexOf('script.js')!==-1;" +
        "})()"
    val result = suspendCancellableCoroutine<String?> { cont ->
        webView.post {
            runCatching {
                webView.evaluateJavascript(script) { value ->
                    if (cont.isActive) cont.resume(value)
                }
            }.onFailure { if (cont.isActive) cont.resume(null) }
        }
    }
    return result?.trim()?.trim('"') == "true"
}

@Composable
internal fun BrowserLoginScreen(
    startUrl: String,
    busy: Boolean,
    errorMessage: String? = null,
    onSessionCaptured: (String, JSONObject?) -> Unit,
    onCanceled: () -> Unit,
    onOpenLogs: () -> Unit = {},
    /** Session token whose native exchange died on an interactive
     *  CAPTCHA. When non-null the screen is the manual verification
     *  step (v1.0.36): the WebView shows the Firefox host that
     *  serves the challenge so the user can pass it by hand, and
     *  [onChallengePassed] fires when the check is seen to pass (or
     *  the user taps Continue) so the caller can harvest the
     *  browser's cookies and retry the exchange once. */
    challengeToken: String? = null,
    onChallengePassed: () -> Unit = {},
    /** Session token whose native exchange FxA refused with
     *  errno 104 "Unconfirmed session". When non-null the screen
     *  is the waiting-for-email-confirmation mode (v1.0.38): the
     *  WebView shows Mozilla's sign-in page so the user can enter
     *  the emailed confirmation code there (iFoxy never sees the
     *  code), and [onConfirmationPassed] fires when the page's
     *  verification hooks report the session confirmed — or when
     *  the user taps Continue — so the caller can retry the
     *  exchange with the kept token. The callback's argument is
     *  true for a manual Continue tap, false for an automatic
     *  page-side detection. */
    unconfirmedToken: String? = null,
    onConfirmationPassed: (manual: Boolean) -> Unit = {},
    exchangeToken: (suspend (String, WebView, WebChannelBridge) -> JSONObject?)? = null,
) {
    var webViewInstance by remember { mutableStateOf<WebView?>(null) }
    var bridgeInstance by remember { mutableStateOf<WebChannelBridge?>(null) }
    var pageTitle by remember { mutableStateOf("") }
    var pageProgress by remember { mutableIntStateOf(0) }
    var pageLoaded by remember { mutableStateOf(false) }
    // Main-frame load failures (no network, HTTP error from Mozilla):
    // without this the user stares at a blank WebView with a stuck
    // progress bar and no way forward.
    var loadError by remember { mutableStateOf<String?>(null) }
    val currentOnSession by rememberUpdatedState(onSessionCaptured)
    val currentOnCanceled by rememberUpdatedState(onCanceled)
    val currentExchange by rememberUpdatedState(exchangeToken)
    val currentOnChallengePassed by rememberUpdatedState(onChallengePassed)
    // Manual verification step state (v1.0.36): the WebView is
    // showing the Firefox page for the check, not a sign-in form.
    val inChallengeMode = challengeToken != null
    var challengeContinueFired by remember { mutableStateOf(false) }
    val currentOnConfirmationPassed by rememberUpdatedState(onConfirmationPassed)
    // Waiting-for-confirmation state (v1.0.38): the WebView is
    // showing Mozilla's sign-in page so the emailed confirmation
    // code can be entered on it.
    val inUnconfirmedMode = unconfirmedToken != null
    var confirmationAutoFired by remember { mutableStateOf(false) }
    var exchanging by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()

    fun fireChallengePassed() {
        if (challengeContinueFired) return
        challengeContinueFired = true
        currentOnChallengePassed()
    }

    fun fireConfirmationPassed(manual: Boolean) {
        // Automatic (page-hook) signals fire at most once: the
        // page can report verification repeatedly, and the caller
        // gives the mode a single automatic retry. Manual Continue
        // taps always go through — re-attempting is the user's
        // own call.
        if (!manual) {
            if (confirmationAutoFired) return
            confirmationAutoFired = true
        }
        currentOnConfirmationPassed(manual)
    }

    // The FxA page carries the user's password / verification code:
    // keep it out of screenshots and the Recents thumbnail while this
    // screen is composed.
    val context = LocalContext.current
    DisposableEffect(Unit) {
        val window = (context as? android.app.Activity)?.window
        window?.addFlags(android.view.WindowManager.LayoutParams.FLAG_SECURE)
        onDispose {
            window?.clearFlags(android.view.WindowManager.LayoutParams.FLAG_SECURE)
        }
    }

    // This screen's background is always the dark brand color, but the
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

    // While the token exchange runs, the user is locked in (Back is
    // swallowed); if it drags past ~10 s, offer an explicit escape.
    var exchangeSlow by remember { mutableStateOf(false) }
    LaunchedEffect(exchanging) {
        exchangeSlow = false
        if (exchanging) {
            delay(10_000)
            exchangeSlow = true
        }
    }

    LaunchedEffect(errorMessage) {
        if (errorMessage != null) exchanging = false
    }

    // Manual verification watch (v1.0.36): while the challenge step
    // is up, poll the accounts page the WebView is showing; once a
    // finished load there is no longer a challenge page, the user
    // has passed and sign-in continues. Auto-detection stops at the
    // deadline — the Continue button below remains as the fallback.
    LaunchedEffect(challengeToken) {
        if (challengeToken == null) return@LaunchedEffect
        val deadline = System.currentTimeMillis() + MANUAL_CHALLENGE_TIMEOUT_MS
        while (System.currentTimeMillis() < deadline) {
            delay(CHALLENGE_CLEARANCE_POLL_MS)
            val webView = webViewInstance ?: continue
            val host = webView.url?.let { runCatching { Uri.parse(it).host }.getOrNull() }
            if (host != "accounts.firefox.com" || !pageLoaded) continue
            val stillChallenged =
                withTimeoutOrNull(5_000) { webViewShowsFastlyChallenge(webView) } ?: true
            AppLogger.i(
                "BrowserLoginScreen",
                "manual verification poll: accounts page still challenged=$stillChallenged",
            )
            if (!stillChallenged) {
                AppLogger.i(
                    "BrowserLoginScreen",
                    "manual Fastly verification passed; continuing sign-in",
                )
                fireChallengePassed()
                return@LaunchedEffect
            }
        }
        AppLogger.w(
            "BrowserLoginScreen",
            "manual Fastly verification was not confirmed automatically; " +
                "the Continue button remains available",
        )
    }

    // Waiting-for-confirmation watch (v1.0.38): the page-side
    // verify hooks release the bridge's parked token into
    // handleSession, which routes it to the confirmation
    // callback — but this mode rebuilds the screen with a fresh
    // WebView whose bridge may hold no parked token for the hooks
    // to release (the page can resume the session from its own
    // storage after the code is entered). Watch the URL for the
    // same success markers the WebViewClient checks so a
    // completed confirmation is still noticed; the Continue
    // button below remains as the fallback.
    LaunchedEffect(unconfirmedToken) {
        if (unconfirmedToken == null) return@LaunchedEffect
        val deadline = System.currentTimeMillis() + MANUAL_CHALLENGE_TIMEOUT_MS
        while (System.currentTimeMillis() < deadline) {
            delay(CHALLENGE_CLEARANCE_POLL_MS)
            val webView = webViewInstance ?: continue
            if (isSuccessUrl(webView.url)) {
                AppLogger.i(
                    "BrowserLoginScreen",
                    "email confirmation completed on Mozilla's page; continuing sign-in",
                )
                fireConfirmationPassed(manual = false)
                return@LaunchedEffect
            }
        }
        AppLogger.w(
            "BrowserLoginScreen",
            "email confirmation was not confirmed automatically; " +
                "the Continue button remains available",
        )
    }

    BackHandler(enabled = true) {
        if (webViewInstance?.canGoBack() == true) {
            webViewInstance?.goBack()
        } else if (!busy && !exchanging) {
            currentOnCanceled()
        }
    }

    fun handleSession(token: String) {
        // Manual verification step: the page context is the
        // challenge, not a sign-in — a WebChannel session message
        // here must not start another exchange.
        if (inChallengeMode) return
        if (inUnconfirmedMode) {
            // Waiting for email confirmation: the page reporting a
            // session here is the confirmation signal, not the
            // start of a competing exchange. The KEPT token routes
            // to the caller's confirmation callback (which retries
            // it); a DIFFERENT token means the user signed in
            // afresh on the page — hand it over as a normal
            // capture so the caller can complete that sign-in.
            if (token == unconfirmedToken) {
                fireConfirmationPassed(manual = false)
            } else {
                currentOnSession(token, null)
            }
            return
        }
        if (busy || exchanging) return
        val exchange = currentExchange
        val view = webViewInstance
        val bridge = bridgeInstance
        if (exchange == null || view == null || bridge == null) {
            currentOnSession(token, null)
            return
        }
        // Preferred path: exchange the session token for OAuth tokens
        // inside the signed-in page (trusted network context); a null
        // result tells the caller to run the native exchange instead.
        exchanging = true
        scope.launch {
            val json = runCatching { exchange(token, view, bridge) }
                .onFailure { AppLogger.w("BrowserLoginScreen", "in-page token exchange threw", it) }
                .getOrNull()
            currentOnSession(token, json)
        }
    }

    Column(
        Modifier
            .fillMaxSize()
            .background(IFoxyBgDark)
            .statusBarsPadding()
            .navigationBarsPadding()
            .imePadding(),
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier
                .fillMaxWidth()
                .padding(start = 4.dp, end = 16.dp, top = 4.dp, bottom = 4.dp),
        ) {
            IconButton(
                onClick = {
                    if (webViewInstance?.canGoBack() == true) {
                        webViewInstance?.goBack()
                    } else if (!busy && !exchanging) {
                        currentOnCanceled()
                    }
                },
                enabled = !busy && !exchanging,
            ) {
                Icon(
                    Icons.AutoMirrored.Filled.ArrowBack,
                    contentDescription = "Back",
                    tint = Color.White,
                )
            }
            Column(Modifier.weight(1f)) {
                Text(
                    pageTitle.ifBlank { "Sign in with Firefox" },
                    style = TextStyle(
                        fontFamily = PoppinsFamily,
                        fontWeight = FontWeight.SemiBold,
                        fontSize = 16.sp,
                    ),
                    color = Color.White,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Text(
                    "You will return to iFoxy automatically after signing in",
                    style = TextStyle(
                        fontFamily = PoppinsFamily,
                        fontWeight = FontWeight.Normal,
                        fontSize = 12.sp,
                    ),
                    color = Color.White.copy(alpha = 0.55f),
                )
            }
        }
        if (busy || exchanging) {
            LinearProgressIndicator(
                color = IFoxyYellow,
                modifier = Modifier.fillMaxWidth(),
            )
            Text(
                "Finishing sign-in securely\u2026",
                style = TextStyle(
                    fontFamily = PoppinsFamily,
                    fontWeight = FontWeight.Normal,
                    fontSize = 12.sp,
                ),
                color = Color.White.copy(alpha = 0.65f),
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 6.dp),
            )
            if (exchanging && exchangeSlow) {
                TextButton(
                    onClick = {
                        exchanging = false
                        currentOnCanceled()
                    },
                    modifier = Modifier.padding(horizontal = 8.dp),
                ) {
                    Text(
                        "Cancel and try again",
                        color = IFoxyYellow,
                        style = TextStyle(
                            fontFamily = PoppinsFamily,
                            fontWeight = FontWeight.SemiBold,
                            fontSize = 12.5.sp,
                        ),
                    )
                }
            }
        } else if (!pageLoaded || pageProgress < 100) {
            LinearProgressIndicator(
                progress = { pageProgress / 100f },
                color = IFoxyYellow,
                modifier = Modifier.fillMaxWidth(),
            )
        }
        if (inChallengeMode) {
            // Manual verification step (v1.0.36): the WebView below
            // is showing Mozilla's page so the user can pass the
            // CAPTCHA its bot protection demanded. The watch above
            // continues sign-in by itself once the check passes;
            // Continue is the manual fallback.
            Text(
                "Mozilla's bot protection needs a human check",
                style = TextStyle(
                    fontFamily = PoppinsFamily,
                    fontWeight = FontWeight.SemiBold,
                    fontSize = 13.5.sp,
                ),
                color = Color.White,
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 6.dp),
            )
            Text(
                "Complete the verification on the Firefox page below. iFoxy retries " +
                    "your sign-in automatically once the check passes — or tap " +
                    "Continue when the page has finished loading.",
                style = TextStyle(
                    fontFamily = PoppinsFamily,
                    fontWeight = FontWeight.Normal,
                    fontSize = 12.5.sp,
                ),
                color = Color.White.copy(alpha = 0.65f),
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp),
            )
            TextButton(
                onClick = {
                    AppLogger.i(
                        "BrowserLoginScreen",
                        "manual Fastly verification continued by the user",
                    )
                    fireChallengePassed()
                },
                modifier = Modifier.padding(horizontal = 8.dp),
            ) {
                Text(
                    "Continue",
                    color = IFoxyYellow,
                    style = TextStyle(
                        fontFamily = PoppinsFamily,
                        fontWeight = FontWeight.SemiBold,
                        fontSize = 12.5.sp,
                    ),
                )
            }
        }
        if (inUnconfirmedMode) {
            // Waiting for email confirmation (v1.0.38): Mozilla
            // emailed a confirmation code and the session cannot be
            // exchanged until it is entered. The WebView below
            // shows Mozilla's page so the code is entered there —
            // iFoxy never sees it. The watch above continues
            // sign-in by itself once the confirmation lands;
            // Continue is the manual fallback.
            Text(
                "Mozilla emailed you a confirmation code",
                style = TextStyle(
                    fontFamily = PoppinsFamily,
                    fontWeight = FontWeight.SemiBold,
                    fontSize = 13.5.sp,
                ),
                color = Color.White,
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 6.dp),
            )
            Text(
                "Enter the code on the Firefox page below to confirm this " +
                    "sign-in. iFoxy retries your sign-in automatically once " +
                    "the confirmation completes — or tap Continue after " +
                    "entering the code.",
                style = TextStyle(
                    fontFamily = PoppinsFamily,
                    fontWeight = FontWeight.Normal,
                    fontSize = 12.5.sp,
                ),
                color = Color.White.copy(alpha = 0.65f),
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp),
            )
            TextButton(
                onClick = {
                    AppLogger.i(
                        "BrowserLoginScreen",
                        "email confirmation continued by the user",
                    )
                    fireConfirmationPassed(manual = true)
                },
                modifier = Modifier.padding(horizontal = 8.dp),
            ) {
                Text(
                    "Continue",
                    color = IFoxyYellow,
                    style = TextStyle(
                        fontFamily = PoppinsFamily,
                        fontWeight = FontWeight.SemiBold,
                        fontSize = 12.5.sp,
                    ),
                )
            }
        }
        if (errorMessage != null) {
            Text(
                text = errorMessage,
                color = IFoxyErrorOnDark,
                style = TextStyle(
                    fontFamily = PoppinsFamily,
                    fontWeight = FontWeight.Medium,
                    fontSize = 12.5.sp,
                ),
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 8.dp)
                    .semantics { liveRegion = LiveRegionMode.Polite },
            )
            // Sign-in failures must not lock the user out of diagnostics:
            // the logs are reachable straight from the error state.
            TextButton(
                onClick = onOpenLogs,
                modifier = Modifier.padding(horizontal = 8.dp),
            ) {
                Text(
                    "Open logs",
                    color = IFoxyYellow,
                    style = TextStyle(
                        fontFamily = PoppinsFamily,
                        fontWeight = FontWeight.SemiBold,
                        fontSize = 12.5.sp,
                    ),
                )
            }
        }
        if (loadError != null) {
            // The page itself failed to load (offline, HTTP error): the
            // WebView below is blank, so the only useful actions are
            // retrying the load or opening diagnostics.
            Text(
                text = loadError.orEmpty(),
                color = IFoxyErrorOnDark,
                style = TextStyle(
                    fontFamily = PoppinsFamily,
                    fontWeight = FontWeight.Medium,
                    fontSize = 12.5.sp,
                ),
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 8.dp)
                    .semantics { liveRegion = LiveRegionMode.Polite },
            )
            Row(Modifier.padding(horizontal = 8.dp)) {
                TextButton(onClick = { webViewInstance?.reload() }) {
                    Text(
                        "Retry",
                        color = IFoxyYellow,
                        style = TextStyle(
                            fontFamily = PoppinsFamily,
                            fontWeight = FontWeight.SemiBold,
                            fontSize = 12.5.sp,
                        ),
                    )
                }
                TextButton(onClick = onOpenLogs) {
                    Text(
                        "Open logs",
                        color = IFoxyYellow,
                        style = TextStyle(
                            fontFamily = PoppinsFamily,
                            fontWeight = FontWeight.SemiBold,
                            fontSize = 12.5.sp,
                        ),
                    )
                }
            }
        }
        Box(Modifier.weight(1f)) {
            AndroidView(
                factory = { context ->
                    WebView(context).apply {
                        webViewInstance = this
                        settings.javaScriptEnabled = true
                        settings.domStorageEnabled = true
                        // The FxA page never needs local files or
                        // content providers; deny both explicitly
                        // instead of relying on platform defaults.
                        settings.allowFileAccess = false
                        @Suppress("DEPRECATION")
                        settings.allowContentAccess = false
                        settings.loadWithOverviewMode = true
                        settings.useWideViewPort = true
                        settings.userAgentString = FIREFOX_ANDROID_UA
                        val cookieManager = CookieManager.getInstance()
                        cookieManager.setAcceptCookie(true)
                        cookieManager.setAcceptThirdPartyCookies(this, true)
                        val bridge = WebChannelBridge(this, ::handleSession)
                        bridgeInstance = bridge
                        addJavascriptInterface(bridge, "foxyWebChannel")
                        webViewClient = object : WebViewClient() {
                            override fun shouldOverrideUrlLoading(
                                view: WebView,
                                request: WebResourceRequest,
                            ): Boolean {
                                val host = request.url.host?.lowercase().orEmpty()
                                if (host == "accounts.firefox.com" || host.endsWith(".firefox.com")) {
                                    return false
                                }
                                runCatching {
                                    val intent = Intent(Intent.ACTION_VIEW, request.url).apply {
                                        addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                                    }
                                    view.context.startActivity(intent)
                                }
                                return true
                            }

                            override fun doUpdateVisitedHistory(
                                view: WebView,
                                url: String?,
                                isReload: Boolean,
                            ) {
                                super.doUpdateVisitedHistory(view, url, isReload)
                                if (isSuccessUrl(url)) {
                                    bridge.onSessionVerified()
                                }
                            }

                            override fun onPageStarted(
                                view: WebView,
                                url: String?,
                                favicon: android.graphics.Bitmap?,
                            ) {
                                super.onPageStarted(view, url, favicon)
                                pageLoaded = false
                                loadError = null
                                if (isSuccessUrl(url)) {
                                    bridge.onSessionVerified()
                                }
                                runCatching { view.evaluateJavascript(WEBCHANNEL_HOOK_JS, null) }
                            }

                            override fun onReceivedError(
                                view: WebView,
                                request: WebResourceRequest?,
                                error: WebResourceError?,
                            ) {
                                super.onReceivedError(view, request, error)
                                // Subresource failures are routine (trackers,
                                // fonts); only a main-frame failure strands
                                // the user on a dead page. While a token
                                // exchange is running, its own API-host
                                // navigation must not raise this either.
                                if (request?.isForMainFrame == true && !exchanging) {
                                    loadError = error?.description?.toString()
                                        ?.takeIf { it.isNotBlank() }
                                        ?: "Couldn't load the sign-in page. " +
                                            "Check your connection and try again."
                                }
                            }

                            override fun onReceivedHttpError(
                                view: WebView,
                                request: WebResourceRequest?,
                                errorResponse: WebResourceResponse?,
                            ) {
                                super.onReceivedHttpError(view, request, errorResponse)
                                if (request?.isForMainFrame == true && !exchanging) {
                                    val status = errorResponse?.statusCode
                                    loadError = if (status != null) {
                                        "The sign-in page could not be loaded (HTTP $status). " +
                                            "Please try again."
                                    } else {
                                        "The sign-in page could not be loaded. Please try again."
                                    }
                                }
                            }

                            override fun onPageFinished(view: WebView, url: String?) {
                                super.onPageFinished(view, url)
                                pageLoaded = true
                                pageTitle = view.title.orEmpty()
                                if (isSuccessUrl(url)) {
                                    bridge.onSessionVerified()
                                }
                                runCatching { view.evaluateJavascript(WEBCHANNEL_HOOK_JS, null) }
                            }
                        }
                        webChromeClient = object : WebChromeClient() {
                            override fun onProgressChanged(view: WebView?, newProgress: Int) {
                                pageProgress = newProgress
                            }

                            override fun onConsoleMessage(message: android.webkit.ConsoleMessage?): Boolean {
                                message?.message()?.let { AppLogger.d(TAG, "console: $it") }
                                return super.onConsoleMessage(message)
                            }
                        }
                        loadUrl(startUrl)
                    }
                },
                modifier = Modifier.fillMaxSize(),
                onRelease = { view ->
                    webViewInstance = null
                    bridgeInstance = null
                    view.stopLoading()
                    view.destroy()
                },
            )
        }
    }
}
