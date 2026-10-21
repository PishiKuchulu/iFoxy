package com.pishi.ifoxy.vpn

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request
import java.net.InetSocketAddress
import java.net.Proxy
import java.util.concurrent.TimeUnit

private const val EXIT_CHECK_URL = "https://www.cloudflare.com/cdn-cgi/trace"

private const val EXIT_CHECK_TIMEOUT_SECONDS = 15L

data class IpLocationInfo(
    val ip: String,
    val countryCode: String,
)

class ExitCheck {

    suspend fun fetchDirectIpInfo(): Result<IpLocationInfo> = withContext(Dispatchers.IO) {
        val client = OkHttpClient.Builder()
            .connectTimeout(8, TimeUnit.SECONDS)
            .readTimeout(8, TimeUnit.SECONDS)
            .callTimeout(8, TimeUnit.SECONDS)
            .build()
        try {
            runCatching {
                val request = Request.Builder().url(EXIT_CHECK_URL).build()
                client.newCall(request).execute().use { response ->
                    if (!response.isSuccessful) error("Direct IP check request failed: HTTP ${response.code}")
                    parseTrace(response.body?.string().orEmpty())
                }
            }
        } finally {
            client.dispatcher.executorService.shutdown()
            client.connectionPool.evictAll()
        }
    }

    suspend fun fetchProxiedIpInfo(socksPort: Int): Result<IpLocationInfo> = withContext(Dispatchers.IO) {
        val proxy = Proxy(Proxy.Type.SOCKS, InetSocketAddress("127.0.0.1", socksPort))
        val client = OkHttpClient.Builder()
            .proxy(proxy)
            .connectTimeout(EXIT_CHECK_TIMEOUT_SECONDS, TimeUnit.SECONDS)
            .readTimeout(EXIT_CHECK_TIMEOUT_SECONDS, TimeUnit.SECONDS)
            .callTimeout(EXIT_CHECK_TIMEOUT_SECONDS, TimeUnit.SECONDS)
            .build()
        try {
            runCatching {
                val request = Request.Builder().url(EXIT_CHECK_URL).build()
                client.newCall(request).execute().use { response ->
                    if (!response.isSuccessful) error("Proxied exit check failed: HTTP ${response.code}")
                    parseTrace(response.body?.string().orEmpty())
                }
            }
        } finally {
            client.dispatcher.executorService.shutdown()
            client.connectionPool.evictAll()
        }
    }

    suspend fun verifyExitCountry(socksPort: Int, expectedCountryCode: String?): Result<String> =
        fetchProxiedIpInfo(socksPort).mapCatching { info ->
            val actualCountry = info.countryCode
            if (expectedCountryCode != null &&
                !expectedCountryCode.equals("REC", ignoreCase = true) &&
                !actualCountry.equals(expectedCountryCode, ignoreCase = true)
            ) {
                error("Exit country mismatch: expected $expectedCountryCode, got $actualCountry")
            }
            actualCountry
        }

    private fun parseTrace(body: String): IpLocationInfo {
        var ip = ""
        var loc = ""
        for (line in body.lineSequence()) {
            if (line.startsWith("ip=")) {
                ip = line.removePrefix("ip=").trim()
            } else if (line.startsWith("loc=")) {
                loc = line.removePrefix("loc=").trim()
            }
        }
        if (ip.isEmpty() && loc.isEmpty()) {
            error("Trace response did not contain IP or location")
        }
        return IpLocationInfo(ip = ip, countryCode = loc)
    }
}
