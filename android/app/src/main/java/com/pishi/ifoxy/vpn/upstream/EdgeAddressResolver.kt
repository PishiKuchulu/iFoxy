package com.pishi.ifoxy.vpn.upstream

import com.pishi.ifoxy.data.AppLogger
import com.pishi.ifoxy.data.ControlPlaneHttp
import com.pishi.ifoxy.data.SettingsStore
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import okhttp3.Call
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.net.InetAddress
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

private const val TAG = "EdgeAddressResolver"

private const val DNS_MESSAGE_CONTENT_TYPE = "application/dns-message"
private val dnsMessageMediaType = DNS_MESSAGE_CONTENT_TYPE.toMediaType()

private const val DOH_PATH = "/dns-query"

private const val DNS_QUERY_ID = 0
private const val DNS_FLAGS_RECURSION_DESIRED = 0x0100
private const val DNS_HEADER_BYTES = 12
private const val DNS_QUESTION_TRAILER_BYTES = 4
private const val DNS_RECORD_HEADER_BYTES = 10
private const val DNS_TYPE_A = 1
private const val DNS_TYPE_AAAA = 28
private const val DNS_CLASS_IN = 1
private const val DNS_RCODE_MASK = 0x0F
private const val DNS_LABEL_MAX_BYTES = 63
private const val DNS_NAME_MAX_BYTES = 255
private const val DNS_COMPRESSION_POINTER_MASK = 0xC0
private const val IPV4_ADDRESS_BYTES = 4
private const val IPV6_ADDRESS_BYTES = 16
private const val ASCII_LIMIT = 128

private const val CONNECT_TIMEOUT_SECONDS = 3L
private const val CALL_TIMEOUT_SECONDS = 3L

private const val MAX_RESPONSE_BYTES = 4096
private const val READ_CHUNK_BYTES = 2048

private const val CACHE_TTL_MS = 5 * 60_000L

private const val FAILURE_BACKOFF_MS = 30 * 60_000L

internal object EdgeAddressResolver {

    /** The cache stores the two families separately: the ORDER
     *  they are dialed in is a function of the caller's
     *  [SettingsStore.IpVersionMode], which can change between
     *  connects while the cached resolution is still fresh. */
    private class CacheEntry(
        val v4Addresses: List<String>,
        val v6Addresses: List<String>,
        val resolvedAtMs: Long,
    )

    private val cache = ConcurrentHashMap<String, CacheEntry>()

    private val suppressedUntilMs = ConcurrentHashMap<String, Long>()

    private val client: OkHttpClient by lazy {
        ControlPlaneHttp.client.newBuilder()
            .connectTimeout(CONNECT_TIMEOUT_SECONDS, TimeUnit.SECONDS)
            .readTimeout(CALL_TIMEOUT_SECONDS, TimeUnit.SECONDS)
            .callTimeout(CALL_TIMEOUT_SECONDS, TimeUnit.SECONDS)
            .build()
    }

    /** Resolves [hostname] over DNS-over-HTTPS and returns the
     *  addresses ORDERED for dialing under [mode] (see
     *  [orderEdgeAddresses]); an empty list means no usable
     *  addresses were obtained and the caller falls back to the
     *  mode-ordered system resolver. Both families are always
     *  fetched — the pre-1.0.37 resolver returned the A set alone
     *  whenever it was non-empty, which made every IPv6 mode a
     *  no-op. */
    suspend fun resolve(
        hostname: String,
        endpointAddresses: List<String>,
        mode: SettingsStore.IpVersionMode,
    ): List<String> {
        if (endpointAddresses.isEmpty()) return emptyList()

        val host = hostname.trim().lowercase()
        if (host.isEmpty()) return emptyList()

        if (host.any { it.code >= ASCII_LIMIT }) return emptyList()

        if (isAddressLiteral(host)) return emptyList()

        cache[host]?.let { cached ->
            if (System.currentTimeMillis() - cached.resolvedAtMs < CACHE_TTL_MS) {
                return orderEdgeAddresses(cached.v4Addresses, cached.v6Addresses, mode)
            }
        }

        val endpoints = endpointAddresses
            .mapNotNull { endpointUrlFor(it) }
            .distinct()
            .filterNot { isSuppressed(it) }
        if (endpoints.isEmpty()) {

            AppLogger.d(TAG, "skipping DNS-over-HTTPS for $host; every configured endpoint is in backoff")
            return emptyList()
        }

        val (v4Addresses, v6Addresses) = queryEndpoints(host, endpoints)
        if (v4Addresses.isEmpty() && v6Addresses.isEmpty()) {
            AppLogger.i(
                TAG,
                "could not resolve $host over DNS-over-HTTPS (tried ${endpoints.size} endpoint(s)); " +
                    "falling back to the system resolver",
            )
            return emptyList()
        }
        cache[host] = CacheEntry(v4Addresses, v6Addresses, System.currentTimeMillis())
        return orderEdgeAddresses(v4Addresses, v6Addresses, mode)
    }

    fun invalidate() {
        cache.clear()
    }

    /** Races the endpoints as before (first endpoint answering with
     *  at least one address in either family wins), but an attempt
     *  now yields BOTH families from that endpoint. */
    private suspend fun queryEndpoints(
        host: String,
        endpoints: List<String>,
    ): Pair<List<String>, List<String>> = coroutineScope {
        val queryV4 = buildQuery(host, DNS_TYPE_A) ?: return@coroutineScope emptyList<String>() to emptyList<String>()
        val queryV6 = buildQuery(host, DNS_TYPE_AAAA) ?: return@coroutineScope emptyList<String>() to emptyList<String>()

        val inFlight = ConcurrentHashMap<String, Call>()

        val winner = CompletableDeferred<Pair<String, Pair<List<String>, List<String>>>?>()
        val outstanding = AtomicInteger(endpoints.size)

        val attempts = endpoints.map { endpoint ->
            launch(Dispatchers.IO) {
                val families = queryOne(endpoint, queryV4, queryV6, inFlight)
                if (families == null) {

                    suppressedUntilMs[endpoint] = System.currentTimeMillis() + FAILURE_BACKOFF_MS
                } else if (families.first.isNotEmpty() || families.second.isNotEmpty()) {
                    suppressedUntilMs.remove(endpoint)

                    winner.complete(endpoint to families)
                    return@launch
                }

                if (outstanding.decrementAndGet() == 0) winner.complete(null)
            }
        }

        try {
            val result = winner.await()
            if (result == null) {
                emptyList<String>() to emptyList<String>()
            } else {
                val (endpoint, families) = result
                AppLogger.d(
                    TAG,
                    "resolved $host over DNS-over-HTTPS via $endpoint " +
                        "(${families.first.size} IPv4 + ${families.second.size} IPv6 address(es))",
                )
                families
            }
        } finally {

            inFlight.values.forEach { runCatching { it.cancel() } }
            attempts.forEach { it.cancel() }
        }
    }

    /** One endpoint's answer: (A list, AAAA list), or null when the
     *  endpoint itself is unusable (its A query failed in
     *  transport — the failure that earns the 30-minute backoff).
     *  Both families are queried unconditionally; an AAAA transport
     *  failure degrades to an empty IPv6 set, mirroring the old
     *  fallback behaviour. */
    private fun queryOne(
        endpoint: String,
        queryV4: ByteArray,
        queryV6: ByteArray,
        inFlight: ConcurrentHashMap<String, Call>,
    ): Pair<List<String>, List<String>>? {
        val v4Response = runCatching { post(endpoint, queryV4, inFlight) }.getOrElse { throwable ->
            AppLogger.d(TAG, "DoH endpoint $endpoint unusable: ${throwable.message}")
            return null
        }
        val v4 = parseAddresses(v4Response, DNS_TYPE_A)

        val v6Response = runCatching { post(endpoint, queryV6, inFlight) }.getOrNull()
        val v6 = if (v6Response != null) parseAddresses(v6Response, DNS_TYPE_AAAA) else emptyList()
        return v4 to v6
    }

    private fun post(endpoint: String, query: ByteArray, inFlight: ConcurrentHashMap<String, Call>): ByteArray {
        val request = Request.Builder()
            .url(endpoint)
            .header("Accept", DNS_MESSAGE_CONTENT_TYPE)
            .post(query.toRequestBody(dnsMessageMediaType))
            .build()
        val call = client.newCall(request)
        inFlight[endpoint] = call
        try {
            call.execute().use { response ->
                if (!response.isSuccessful) error("HTTP ${response.code}")
                val body = response.body ?: error("DoH response had no body")
                return body.byteStream().readBounded(MAX_RESPONSE_BYTES)
            }
        } finally {
            inFlight.remove(endpoint, call)
        }
    }

    private fun isSuppressed(endpoint: String): Boolean =
        (suppressedUntilMs[endpoint] ?: 0L) > System.currentTimeMillis()

    private fun endpointUrlFor(address: String): String? {
        val host = address.trim().lowercase()
        if (!isAddressLiteral(host)) return null

        val authority = if (host.contains(':')) "[$host]" else host
        return "https://$authority$DOH_PATH"
    }
}

/** Orders/filters a resolved (A, AAAA) pair into the dial order
 *  for [mode] — the single source of truth every resolution path
 *  (DoH, system fallback, cache) shapes its result with. Pure:
 *  unit-tested for all five modes. DUAL_STACK keeps both families
 *  (list order is irrelevant there — the session races the first
 *  address of each family). */
internal fun orderEdgeAddresses(
    v4Addresses: List<String>,
    v6Addresses: List<String>,
    mode: SettingsStore.IpVersionMode,
): List<String> = when (mode) {
    SettingsStore.IpVersionMode.AUTO,
    SettingsStore.IpVersionMode.DUAL_STACK,
    -> v4Addresses + v6Addresses
    SettingsStore.IpVersionMode.IPV6_FIRST -> v6Addresses + v4Addresses
    SettingsStore.IpVersionMode.IPV4_ONLY -> v4Addresses
    SettingsStore.IpVersionMode.IPV6_ONLY -> v6Addresses
}

private fun buildQuery(hostname: String, type: Int): ByteArray? {
    val labels = hostname.split('.').filter { it.isNotEmpty() }
    if (labels.isEmpty()) return null

    var encodedNameBytes = 1 
    for (label in labels) {
        val bytes = label.toByteArray(Charsets.US_ASCII)
        if (bytes.isEmpty() || bytes.size > DNS_LABEL_MAX_BYTES) return null
        encodedNameBytes += 1 + bytes.size
    }
    if (encodedNameBytes > DNS_NAME_MAX_BYTES) return null

    val out = ByteArrayOutputStream(DNS_HEADER_BYTES + encodedNameBytes + DNS_QUESTION_TRAILER_BYTES)
    fun writeShort(value: Int) {
        out.write((value ushr 8) and 0xFF)
        out.write(value and 0xFF)
    }
    writeShort(DNS_QUERY_ID)
    writeShort(DNS_FLAGS_RECURSION_DESIRED)
    writeShort(1) 
    writeShort(0) 
    writeShort(0) 
    writeShort(0) 
    for (label in labels) {
        val bytes = label.toByteArray(Charsets.US_ASCII)
        out.write(bytes.size)
        out.write(bytes, 0, bytes.size)
    }
    out.write(0)
    writeShort(type)
    writeShort(DNS_CLASS_IN)
    return out.toByteArray()
}

private fun parseAddresses(response: ByteArray, wantType: Int): List<String> {
    if (response.size < DNS_HEADER_BYTES) return emptyList()
    fun u8(index: Int): Int = response[index].toInt() and 0xFF
    fun u16(index: Int): Int = (u8(index) shl 8) or u8(index + 1)

    if (u8(3) and DNS_RCODE_MASK != 0) return emptyList()
    val questionCount = u16(4)
    val answerCount = u16(6)
    if (answerCount == 0) return emptyList()

    var offset = DNS_HEADER_BYTES
    for (i in 0 until questionCount) {
        offset = skipName(response, offset) ?: return emptyList()
        offset += DNS_QUESTION_TRAILER_BYTES
    }

    val expectedRdLength = if (wantType == DNS_TYPE_A) IPV4_ADDRESS_BYTES else IPV6_ADDRESS_BYTES
    val addresses = mutableListOf<String>()
    for (i in 0 until answerCount) {
        offset = skipName(response, offset) ?: return addresses
        if (offset + DNS_RECORD_HEADER_BYTES > response.size) return addresses
        val type = u16(offset)
        val rdLength = u16(offset + 8)
        offset += DNS_RECORD_HEADER_BYTES
        if (offset + rdLength > response.size) return addresses
        if (type == wantType && rdLength == expectedRdLength) {

            runCatching { InetAddress.getByAddress(response.copyOfRange(offset, offset + rdLength)) }
                .getOrNull()
                ?.hostAddress
                ?.let { addresses.add(it) }
        }
        offset += rdLength
    }
    return addresses
}

private fun skipName(message: ByteArray, start: Int): Int? {
    var offset = start
    var consumed = 0
    while (offset < message.size) {
        val length = message[offset].toInt() and 0xFF
        if (length == 0) return offset + 1
        if (length and DNS_COMPRESSION_POINTER_MASK == DNS_COMPRESSION_POINTER_MASK) {
            return if (offset + 2 <= message.size) offset + 2 else null
        }
        if (length > DNS_LABEL_MAX_BYTES) return null
        offset += 1 + length
        consumed += 1 + length
        if (consumed > DNS_NAME_MAX_BYTES) return null
    }
    return null
}

private fun isAddressLiteral(host: String): Boolean {
    if (host.contains(':')) return true
    val parts = host.split('.')
    if (parts.size != IPV4_ADDRESS_BYTES) return false
    return parts.all { part ->
        part.isNotEmpty() && part.length <= 3 && part.all { it.isDigit() } && part.toInt() <= 255
    }
}

private fun InputStream.readBounded(limit: Int): ByteArray {
    val out = ByteArrayOutputStream()
    val buffer = ByteArray(READ_CHUNK_BYTES)
    while (out.size() <= limit) {
        val read = read(buffer)
        if (read < 0) break
        out.write(buffer, 0, read)
    }
    if (out.size() > limit) error("DoH response exceeded $limit bytes")
    return out.toByteArray()
}
