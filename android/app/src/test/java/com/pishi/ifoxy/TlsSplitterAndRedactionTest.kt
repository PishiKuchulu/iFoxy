package com.pishi.ifoxy

import com.pishi.ifoxy.data.SettingsStore
import com.pishi.ifoxy.vpn.upstream.NettyLoggingBridge
import com.pishi.ifoxy.vpn.upstream.TlsClientHelloSplitter
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** TST-FX-11: TLS ClientHello splitting and log redaction (SEC-FX-12). */
class TlsSplitterAndRedactionTest {

    private fun syntheticClientHello(sni: String): ByteArray {
        val name = sni.toByteArray(Charsets.US_ASCII)
        val sniBody = mutableListOf<Byte>()
        val listLen = 1 + 2 + name.size
        sniBody += ((listLen shr 8) and 0xFF).toByte()
        sniBody += (listLen and 0xFF).toByte()
        sniBody += 0.toByte() // host_name
        sniBody += ((name.size shr 8) and 0xFF).toByte()
        sniBody += (name.size and 0xFF).toByte()
        sniBody += name.toList()

        val ext = mutableListOf<Byte>()
        ext += 0.toByte(); ext += 0.toByte() // type 0 (SNI)
        ext += ((sniBody.size shr 8) and 0xFF).toByte()
        ext += (sniBody.size and 0xFF).toByte()
        ext += sniBody

        val body = mutableListOf<Byte>()
        body += 0x03.toByte(); body += 0x03.toByte() // TLS 1.2
        body += ByteArray(32) { 0x42 }.toList() // random
        body += 0.toByte() // session id len
        body += 0.toByte(); body += 2.toByte() // cipher suites len
        body += 0x13.toByte(); body += 0x01.toByte() // TLS_AES_128_GCM
        body += 1.toByte() // compression len
        body += 0.toByte() // null compression
        body += ((ext.size shr 8) and 0xFF).toByte()
        body += (ext.size and 0xFF).toByte()
        body += ext

        val out = mutableListOf<Byte>()
        out += 0x16.toByte() // handshake record
        out += 0x03.toByte(); out += 0x01.toByte() // record version
        val recordLen = 4 + body.size
        out += ((recordLen shr 8) and 0xFF).toByte()
        out += (recordLen and 0xFF).toByte()
        out += 0x01.toByte() // ClientHello
        out += 0.toByte()
        out += ((body.size shr 8) and 0xFF).toByte()
        out += (body.size and 0xFF).toByte()
        out += body
        return out.toByteArray()
    }

    @Test
    fun detectsClientHello() {
        val hello = syntheticClientHello("example.com")
        assertTrue(TlsClientHelloSplitter.looksLikeClientHello(hello))
        assertFalse(TlsClientHelloSplitter.looksLikeClientHello(ByteArray(16) { 0x17 }))
        assertFalse(TlsClientHelloSplitter.looksLikeClientHello(ByteArray(3)))
    }

    @Test
    fun findsSniAndSplitsAroundIt() {
        val hello = syntheticClientHello("example.com")
        val range = TlsClientHelloSplitter.findSniOffset(hello)
        assertNotNull(range)
        val (start, end) = range!!
        assertEquals("example.com", String(hello, start, end - start, Charsets.US_ASCII))

        val segments = TlsClientHelloSplitter.splitBytes(hello, mode = SettingsStore.TlsSplitMode.SNI)
        assertNotNull(segments)
        assertEquals(3, segments!!.size)
        assertEquals(hello.size, segments.sumOf { it.size })
        // Middle segment is exactly the first SNI byte; reassembly is lossless.
        assertEquals("e", String(segments[1], Charsets.US_ASCII))
        val rejoined = segments.fold(ByteArray(0)) { acc, seg -> acc + seg }
        assertTrue(hello.contentEquals(rejoined))
    }

    @Test
    fun firstByteSplitAndOffMode() {
        val hello = syntheticClientHello("a.b")
        val segments = TlsClientHelloSplitter.splitBytes(hello, mode = SettingsStore.TlsSplitMode.FIRST_BYTE)
        assertNotNull(segments)
        assertEquals(1, segments!![0].size)
        assertEquals(hello.size, segments.sumOf { it.size })
        assertNull(TlsClientHelloSplitter.splitBytes(hello, mode = SettingsStore.TlsSplitMode.OFF))
    }

    @Test
    fun redactionCoversBearerHeadersAndJsonTokens() {
        val bearer = NettyLoggingBridge.redactSecrets("proxy-authorization: Bearer abcDEF123._-~+/=")
        assertFalse(bearer.contains("abcDEF123"))

        val basic = NettyLoggingBridge.redactSecrets("Authorization: Basic dXNlcjpwYXNz")
        assertFalse(basic.contains("dXNlcjpwYXNz"))

        val json = NettyLoggingBridge.redactSecrets("""{"access_token":"tok123","refresh_token":"ref456","ok":true}""")
        assertFalse(json.contains("tok123"))
        assertFalse(json.contains("ref456"))
        assertTrue(json.contains("\"ok\":true"))

        val cookie = NettyLoggingBridge.redactSecrets("Cookie: session=deadbeef; theme=dark")
        assertFalse(cookie.contains("deadbeef"))
    }
}
