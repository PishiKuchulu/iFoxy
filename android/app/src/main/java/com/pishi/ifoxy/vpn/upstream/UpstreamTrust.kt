package com.pishi.ifoxy.vpn.upstream

import android.content.Context
import com.pishi.ifoxy.R
import com.pishi.ifoxy.data.AppLogger
import java.io.ByteArrayInputStream
import java.security.KeyStore
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import javax.net.ssl.TrustManagerFactory

private const val TAG = "UpstreamTrust"

private val PEM_BLOCK = Regex("-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", RegexOption.DOT_MATCHES_ALL)

object UpstreamTrust {

    @Volatile private var appContext: Context? = null
    @Volatile private var cached: TrustManagerFactory? = null
    @Volatile private var built = false
    private val lock = Any()

    fun init(context: Context) {
        appContext = context.applicationContext
    }

    fun trustManagerFactory(): TrustManagerFactory? {
        if (built) return cached
        synchronized(lock) {
            if (!built) {
                cached = runCatching { build() }
                    .onFailure { AppLogger.e(TAG, "could not build the merged trust store; using the system default", it) }
                    .getOrNull()
                built = true
            }
            return cached
        }
    }

    private fun build(): TrustManagerFactory? {
        val merged = KeyStore.getInstance(KeyStore.getDefaultType()).apply { load(null, null) }

        var systemCount = 0
        runCatching {
            // Take the platform anchors from the DEFAULT trust manager
            // instead of enumerating AndroidCAStore directly: the raw
            // store also contains user-installed CAs, which the platform
            // policy for this app (no networkSecurityConfig opt-in)
            // does not trust — the merged store silently widened trust
            // to them (external review, A5).
            val platformTmf = TrustManagerFactory
                .getInstance(TrustManagerFactory.getDefaultAlgorithm())
                .apply { init(null as KeyStore?) }
            val platformTm = platformTmf.trustManagers
                .filterIsInstance<javax.net.ssl.X509TrustManager>()
                .firstOrNull()
            val issuers = platformTm?.acceptedIssuers ?: emptyArray()
            for ((index, cert) in issuers.withIndex()) {
                merged.setCertificateEntry("system:$index", cert)
                systemCount++
            }
        }.onFailure {
            AppLogger.w(TAG, "could not read the platform trust anchors; relying on the bundled roots only", it)
        }

        var bundledCount = 0
        val context = appContext
        if (context == null) {
            AppLogger.w(TAG, "no application context; the bundled roots were not loaded")
        } else {
            runCatching {
                val pem = context.resources.openRawResource(R.raw.globalsign_roots).use { it.readBytes() }
                    .toString(Charsets.US_ASCII)
                val factory = CertificateFactory.getInstance("X.509")
                for (block in PEM_BLOCK.findAll(pem)) {
                    runCatching {
                        val cert = factory.generateCertificate(
                            ByteArrayInputStream(block.value.toByteArray(Charsets.US_ASCII)),
                        ) as X509Certificate
                        merged.setCertificateEntry("bundled:$bundledCount", cert)
                        bundledCount++
                    }
                }
            }.onFailure {
                AppLogger.w(TAG, "could not load the bundled GlobalSign roots", it)
            }
        }

        if (systemCount == 0 && bundledCount == 0) return null

        AppLogger.i(TAG, "upstream TLS trust: $systemCount system root(s) + $bundledCount bundled root(s)")
        return TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(merged) }
    }
}
