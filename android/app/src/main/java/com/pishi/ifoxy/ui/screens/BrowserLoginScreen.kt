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

private const val FIREFOX_ANDROID_UA =
    "Mozilla/5.0 (Android 14; Mobile; rv:132.0) Gecko/132.0 Firefox/132.0"

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
internal suspend fun runTokenExchangeInPage(
    webView: WebView,
    bridge: WebChannelBridge,
    spec: BrowserTokenRequest,
): JSONObject? {
    val payload = withTimeoutOrNull(25_000) {
        suspendCancellableCoroutine<String> { cont ->
            bridge.tokenExchangeCallback = { result ->
                if (cont.isActive) cont.resume(result)
            }
            cont.invokeOnCancellation { bridge.tokenExchangeCallback = null }
            val script = "(function(){try{fetch(" + JSONObject.quote(spec.url) +
                ",{method:'POST',headers:{'Content-Type':'application/json','Authorization':" +
                JSONObject.quote(spec.authorization) +
                "},body:" + JSONObject.quote(spec.bodyJson) +
                ",credentials:'omit'}).then(function(r){return r.text().then(function(t){" +
                "window.foxyWebChannel.onTokenExchangeResult(JSON.stringify({status:r.status,body:t}));});})" +
                ".catch(function(e){window.foxyWebChannel.onTokenExchangeResult(JSON.stringify({status:0,body:String(e)}));});" +
                "}catch(e){window.foxyWebChannel.onTokenExchangeResult(JSON.stringify({status:-1,body:String(e)}));}})();"
            webView.post { webView.evaluateJavascript(script, null) }
        }
    } ?: return null
    val outer = runCatching { JSONObject(payload) }.getOrNull() ?: return null
    val status = outer.optInt("status")
    if (status != 200) {
        AppLogger.w(
            "BrowserLoginScreen",
            "in-page token exchange failed: status=$status body=${outer.optString("body").take(200)}",
        )
        return null
    }
    AppLogger.i("BrowserLoginScreen", "in-page token exchange succeeded (HTTP 200)")
    return runCatching { JSONObject(outer.optString("body")) }.getOrNull()
        ?.takeIf { it.optString("access_token").isNotBlank() }
}

@Composable
internal fun BrowserLoginScreen(
    startUrl: String,
    busy: Boolean,
    errorMessage: String? = null,
    onSessionCaptured: (String, JSONObject?) -> Unit,
    onCanceled: () -> Unit,
    onOpenLogs: () -> Unit = {},
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
    var exchanging by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()

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

    BackHandler(enabled = true) {
        if (webViewInstance?.canGoBack() == true) {
            webViewInstance?.goBack()
        } else if (!busy && !exchanging) {
            currentOnCanceled()
        }
    }

    fun handleSession(token: String) {
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
                                // the user on a dead page.
                                if (request?.isForMainFrame == true) {
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
                                if (request?.isForMainFrame == true) {
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
