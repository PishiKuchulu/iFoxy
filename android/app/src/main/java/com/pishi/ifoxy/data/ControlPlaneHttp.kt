package com.pishi.ifoxy.data

import okhttp3.Cookie
import okhttp3.CookieJar
import okhttp3.Dns
import okhttp3.HttpUrl
import okhttp3.OkHttpClient
import okhttp3.Request
import com.pishi.ifoxy.vpn.upstream.TlsClientHelloSplitter
import java.io.FilterOutputStream
import java.io.OutputStream
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketException
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit
import javax.net.SocketFactory

private const val TAG = "ControlPlaneHttp"

const val MOZILLA_VPN_USER_AGENT = "MozillaVPN/2.35.0 (sys:android 14; iap:true)"

/** The Firefox-for-Android user agent the browser sign-in WebView
 *  presents. Shared so the Fastly challenge solver can also probe a
 *  challenged host the way the sign-in browser would. */
const val FIREFOX_ANDROID_UA =
    "Mozilla/5.0 (Android 14; Mobile; rv:132.0) Gecko/132.0 Firefox/132.0"

fun Request.Builder.applyMozillaVpnHeaders(): Request.Builder {
    header("User-Agent", MOZILLA_VPN_USER_AGENT)
    header("Accept", "application/json")
    return this
}

class SimpleCookieJar : CookieJar {
    private val byDomain = ConcurrentHashMap<String, MutableList<Cookie>>()

    override fun saveFromResponse(url: HttpUrl, cookies: List<Cookie>) {
        for (cookie in cookies) {
            val bucket = byDomain.getOrPut(cookie.domain) { mutableListOf() }
            synchronized(bucket) {
                bucket.removeAll { it.name == cookie.name }
                bucket.add(cookie)
            }
        }
    }

    override fun loadForRequest(url: HttpUrl): List<Cookie> {
        val now = System.currentTimeMillis()
        val result = mutableListOf<Cookie>()
        for ((domain, cookies) in byDomain) {
            if (url.host == domain || url.host.endsWith(".$domain")) {
                synchronized(cookies) {
                    result.addAll(
                        cookies.filter { cookie ->
                            // SEC-FX-03: honour the cookie's own constraints —
                            // expiry, Secure (https only) and Path prefix —
                            // instead of sending every stored cookie everywhere
                            // under the domain.
                            cookie.expiresAt > now &&
                                (!cookie.secure || url.isHttps) &&
                                url.encodedPath.startsWith(cookie.path)
                        },
                    )
                }
            }
        }
        return result
    }

    fun set(name: String, value: String, domain: String) {
        val bucket = byDomain.getOrPut(domain) { mutableListOf() }
        synchronized(bucket) {
            bucket.removeAll { it.name == name }
            bucket.add(
                Cookie.Builder()
                    .name(name)
                    .value(value)
                    .domain(domain)
                    .path("/")
                    // SEC-FX-03: challenge cookies are only ever used against
                    // https FxA endpoints; mark them Secure so they can never
                    // be sent over a plaintext request.
                    .secure()
                    .expiresAt(Long.MAX_VALUE)
                    .build(),
            )
        }
    }

    fun snapshotAll(): List<Cookie> = byDomain.values.flatten()
}

private class SplitClientHelloSocket(
    private val modeProvider: () -> SettingsStore.TlsSplitMode,
) : Socket() {
    private var splitDone = false

    override fun getOutputStream(): OutputStream {
        val realOut = super.getOutputStream()
        return object : FilterOutputStream(realOut) {
            override fun write(b: ByteArray, off: Int, len: Int) {
                val mode = modeProvider()
                if (splitDone || mode == SettingsStore.TlsSplitMode.OFF) {
                    realOut.write(b, off, len)
                    return
                }

                if (!TlsClientHelloSplitter.looksLikeClientHello(b, off, len)) {
                    realOut.write(b, off, len)
                    return
                }

                splitDone = true
                val segments = try {
                    TlsClientHelloSplitter.splitBytes(b, off, len, mode)
                } catch (e: Throwable) {
                    null
                }

                if (segments.isNullOrEmpty()) {
                    realOut.write(b, off, len)
                    return
                }

                runCatching { this@SplitClientHelloSocket.tcpNoDelay = true }
                for (seg in segments) {
                    realOut.write(seg)
                    realOut.flush()
                }
            }

            override fun write(b: ByteArray) {
                write(b, 0, b.size)
            }
        }
    }
}

private class ProtectingSocketFactory : SocketFactory() {

    private fun createRawSocket(): Socket =
        SplitClientHelloSocket { ControlPlaneHttp.tlsSplitModeProvider?.invoke() ?: SettingsStore.TlsSplitMode.OFF }

    private fun protect(socket: Socket, localAddress: InetSocketAddress?): Socket {
        runCatching {
            if (!socket.isBound) socket.bind(localAddress ?: InetSocketAddress(0))
        }.onFailure {
            AppLogger.w(TAG, "could not bind a control-plane socket before protecting it", it)
        }
        val protector = ControlPlaneHttp.socketProtector
        if (protector != null) {
            val protectedOk = runCatching { protector.invoke(socket) }.getOrDefault(false)
            if (!protectedOk) {
                // Fail CLOSED (external review, P2): handing the
                // unprotected socket back would route this control-plane
                // request through the tunnel it is supposed to bypass.
                // Close it and fail the request so OkHttp surfaces a
                // connect error instead of silently leaking the path.
                runCatching { socket.close() }
                throw SocketException(
                    "VpnService.protect() refused a control-plane socket; " +
                        "request aborted rather than routing through the tunnel",
                )
            }
        }
        // protector == null is the explicit no-protect path:
        // proxyOnlyMode sets socketProtector = null by design (no TUN
        // exists to leak into), so there is nothing to refuse here.
        return socket
    }

    override fun createSocket(): Socket = protect(createRawSocket(), null)

    override fun createSocket(host: String, port: Int): Socket =
        protect(createRawSocket(), null).apply { connect(InetSocketAddress(host, port)) }

    override fun createSocket(host: String, port: Int, localAddr: InetAddress, localPort: Int): Socket =
        protect(createRawSocket(), InetSocketAddress(localAddr, localPort))
            .apply { connect(InetSocketAddress(host, port)) }

    override fun createSocket(host: InetAddress, port: Int): Socket =
        protect(createRawSocket(), null).apply { connect(InetSocketAddress(host, port)) }

    override fun createSocket(host: InetAddress, port: Int, localAddr: InetAddress, localPort: Int): Socket =
        protect(createRawSocket(), InetSocketAddress(localAddr, localPort))
            .apply { connect(InetSocketAddress(host, port)) }
}

/** Orders/filters system-resolved addresses by the IP version
 *  mode: AUTO and DUAL_STACK keep the system order untouched
 *  (OkHttp already tries addresses in order, and dual-stack on
 *  the control plane has no racing dialer to feed); IPV6_FIRST
 *  moves IPv6 ahead; the ONLY modes filter. Pure: unit-tested.
 *  The data plane's string form of the same semantics is
 *  orderEdgeAddresses (vpn/upstream). */
internal fun orderInetAddresses(
    addresses: List<InetAddress>,
    mode: SettingsStore.IpVersionMode,
): List<InetAddress> = when (mode) {
    SettingsStore.IpVersionMode.AUTO,
    SettingsStore.IpVersionMode.DUAL_STACK,
    -> addresses
    SettingsStore.IpVersionMode.IPV6_FIRST ->
        addresses.filter { it !is Inet4Address } + addresses.filter { it is Inet4Address }
    SettingsStore.IpVersionMode.IPV4_ONLY -> addresses.filter { it is Inet4Address }
    SettingsStore.IpVersionMode.IPV6_ONLY -> addresses.filter { it !is Inet4Address }
}

/** OkHttp DNS that applies the current [SettingsStore.IpVersionMode]
 *  to control-plane lookups, read at call time through
 *  [ControlPlaneHttp.ipVersionModeProvider] (the same provider
 *  pattern as the TLS split mode). Bare IP literals pass through
 *  unfiltered: they need no resolution, and filtering one out (a
 *  configured DoH endpoint under the opposite ONLY mode) would
 *  break the very lookups the mode's own machinery depends on. */
private object IpVersionModeDns : Dns {
    override fun lookup(hostname: String): List<InetAddress> {
        val mode = ControlPlaneHttp.ipVersionModeProvider?.invoke()
            ?: SettingsStore.IpVersionMode.AUTO
        if (isIpLiteralHost(hostname)) return listOf(InetAddress.getByName(hostname))
        return orderInetAddresses(InetAddress.getAllByName(hostname).toList(), mode)
    }
}

private fun isIpLiteralHost(hostname: String): Boolean {
    if (hostname.contains(':')) return true
    val parts = hostname.split('.')
    if (parts.size != 4) return false
    return parts.all { part ->
        part.isNotEmpty() && part.length <= 3 && part.all { it.isDigit() } && part.toInt() <= 255
    }
}

object ControlPlaneHttp {
    val cookieJar = SimpleCookieJar()

    @Volatile
    var socketProtector: ((Socket) -> Boolean)? = null

    @Volatile
    var tlsSplitModeProvider: (() -> SettingsStore.TlsSplitMode)? = null

    @Volatile
    var ipVersionModeProvider: (() -> SettingsStore.IpVersionMode)? = null

    val client: OkHttpClient by lazy {
        OkHttpClient.Builder()
            .cookieJar(cookieJar)
            .dns(IpVersionModeDns)
            .socketFactory(ProtectingSocketFactory())
            .connectTimeout(30, TimeUnit.SECONDS)
            .readTimeout(30, TimeUnit.SECONDS)
            .callTimeout(30, TimeUnit.SECONDS)
            .build()
    }
}
