package com.pishi.ifoxy.vpn.socks

import com.pishi.ifoxy.data.AppLogger
import com.pishi.ifoxy.vpn.RelayDispatchers
import com.pishi.ifoxy.vpn.upstream.UpstreamSession
import kotlinx.coroutines.CoroutineExceptionHandler
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Semaphore
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

private const val TAG = "Socks5UdpDnsRelay"

internal const val DNS_PORT = 53

internal const val MAX_DNS_MESSAGE_BYTES = 4096

private const val SOCKS5_UDP_HEADER_MIN_BYTES = 10

private const val MAX_INFLIGHT_QUERIES = 32

internal class Socks5UdpDnsRelay(
    private val bindAddress: InetAddress,
    private val clientAddress: InetAddress,
    private val socksProxy: InetSocketAddress?,
    private val dohUrl: String? = null,
    private val sessionProvider: () -> UpstreamSession?,
    private val onUnsupportedFlow: () -> Unit = {},
) {

    private val socket = DatagramSocket(0, bindAddress)

    private val inflight = Semaphore(MAX_INFLIGHT_QUERIES)

    private val queriesOverHttps = AtomicInteger(0)
    private val nonDnsDropped = AtomicInteger(0)
    private val foreignSourceDropped = AtomicInteger(0)
    private val otherDropped = AtomicInteger(0)
    private val unsupportedFlowReported = AtomicBoolean(false)

    private val exceptionHandler = CoroutineExceptionHandler { _, throwable ->
        AppLogger.d(TAG, "dropped a DNS datagram: ${throwable.message}")
        otherDropped.incrementAndGet()
    }
    private val scope = CoroutineScope(RelayDispatchers.relay + SupervisorJob() + exceptionHandler)

    val boundAddress: InetAddress get() = bindAddress

    val boundPort: Int get() = socket.localPort

    fun start() {
        AppLogger.d(TAG, "started UDP DNS relay on $bindAddress:${socket.localPort}; upstream DoH=${dohUrl ?: "<per-resolver>"}")
        scope.launch {
            val buffer = ByteArray(MAX_DNS_MESSAGE_BYTES + SOCKS5_UDP_HEADER_MIN_BYTES + 256)
            while (!socket.isClosed) {
                val packet = DatagramPacket(buffer, buffer.size)
                try {
                    socket.receive(packet)
                } catch (e: IOException) {
                    break 
                }

                if (packet.address != clientAddress) {
                    if (foreignSourceDropped.getAndIncrement() == 0) {
                        AppLogger.w(
                            TAG,
                            "dropping a datagram from ${packet.address}: this association belongs to " +
                                "$clientAddress, and relaying for anyone else would make this an open resolver",
                        )
                    }
                    continue
                }

                val targetPort = extractTargetPort(packet.data, packet.offset, packet.length)
                if (targetPort != DNS_PORT) {
                    nonDnsDropped.incrementAndGet()
                    if (unsupportedFlowReported.compareAndSet(false, true)) {
                        AppLogger.d(
                            TAG,
                            "dropping a datagram for port $targetPort: this tunnel carries TCP only, so general " +
                                "UDP (QUIC included) cannot be relayed and the sender has to fall back to TCP. " +
                                "The DNS association stays up.",
                        )
                        runCatching { onUnsupportedFlow() }
                    }
                    continue
                }

                val datagram = packet.data.copyOfRange(packet.offset, packet.offset + packet.length)
                val replyTo = InetSocketAddress(packet.address, packet.port)

                if (!inflight.tryAcquire()) {
                    otherDropped.incrementAndGet()
                    continue
                }
                scope.launch {
                    try {
                        relay(datagram, replyTo)
                    } finally {
                        inflight.release()
                    }
                }
            }
        }
    }

    fun stop() {
        runCatching { socket.close() }
        scope.cancel()
        val https = queriesOverHttps.get()
        val nonDns = nonDnsDropped.get()
        val foreign = foreignSourceDropped.get()
        val other = otherDropped.get()

        if (https > 0 || nonDns > 0 || foreign > 0 || other > 0) {
            AppLogger.d(
                TAG,
                "UDP association closed: $https DNS queries over HTTPS, $nonDns non-DNS datagrams dropped, " +
                    "$foreign from unassociated sources, $other other drops",
            )
        }
    }

    private suspend fun relay(datagram: ByteArray, replyTo: InetSocketAddress) {
        val request = parseRequest(datagram)
        if (request == null) {
            otherDropped.incrementAndGet()
            return
        }

        val query = datagram.copyOfRange(request.payloadOffset, datagram.size)
        if (query.isEmpty() || query.size > MAX_DNS_MESSAGE_BYTES) {
            otherDropped.incrementAndGet()
            return
        }

        val session = sessionProvider()?.takeIf { it.isConnected }
        if (session == null) {
            otherDropped.incrementAndGet()
            return
        }

        val answer = resolve(request.host, query)
        if (answer == null) {
            otherDropped.incrementAndGet()
            return
        }

        val response = datagram.copyOfRange(0, request.payloadOffset) + answer
        runCatching { socket.send(DatagramPacket(response, response.size, replyTo)) }
            .onFailure { otherDropped.incrementAndGet() }
    }

    private fun resolve(
        resolverHost: String,
        query: ByteArray,
    ): ByteArray? {
        if (socksProxy == null) return null
        val endpoint = dohUrl ?: DohDnsClient.endpointFor(resolverHost)
        val answer = DohDnsClient.query(socksProxy, endpoint, query)
        if (answer != null) {
            queriesOverHttps.incrementAndGet()
            return answer
        }
        return null
    }

    private class Request(val payloadOffset: Int, val host: String, val port: Int)

    private fun parseRequest(datagram: ByteArray): Request? {
        if (datagram.size < SOCKS5_UDP_HEADER_MIN_BYTES) return null

        if (datagram[0].toInt() != 0 || datagram[1].toInt() != 0) return null

        if (datagram[2].toInt() != 0) return null

        var offset = 3
        val addressType = datagram[offset++].toInt() and 0xFF
        val host = when (addressType) {
            0x01 -> {
                if (datagram.size < offset + 4 + 2) return null
                val bytes = datagram.copyOfRange(offset, offset + 4)
                offset += 4
                bytes.joinToString(".") { (it.toInt() and 0xFF).toString() }
            }
            0x03 -> {
                val length = datagram[offset++].toInt() and 0xFF
                if (length == 0) return null
                if (datagram.size < offset + length + 2) return null
                val name = String(datagram, offset, length, Charsets.US_ASCII)
                offset += length
                name
            }
            0x04 -> {
                if (datagram.size < offset + 16 + 2) return null
                val bytes = datagram.copyOfRange(offset, offset + 16)
                offset += 16
                InetAddress.getByAddress(bytes).hostAddress ?: return null
            }
            else -> return null
        }
        val port = ((datagram[offset].toInt() and 0xFF) shl 8) or (datagram[offset + 1].toInt() and 0xFF)
        offset += 2
        return Request(offset, host, port)
    }

    private fun extractTargetPort(data: ByteArray, offset: Int, length: Int): Int {
        if (length < SOCKS5_UDP_HEADER_MIN_BYTES) return -1
        if (data[offset].toInt() != 0 || data[offset + 1].toInt() != 0 || data[offset + 2].toInt() != 0) return -1
        var pos = offset + 3
        val addressType = data[pos++].toInt() and 0xFF
        when (addressType) {
            0x01 -> pos += 4
            0x03 -> {
                if (pos >= offset + length) return -1
                val domainLen = data[pos++].toInt() and 0xFF
                pos += domainLen
            }
            0x04 -> pos += 16
            else -> return -1
        }
        if (pos + 2 > offset + length) return -1
        return ((data[pos].toInt() and 0xFF) shl 8) or (data[pos + 1].toInt() and 0xFF)
    }
}
