package com.pishi.ifoxy

import com.pishi.ifoxy.data.FastlyCaptchaException
import com.pishi.ifoxy.data.FastlyChallengeError
import com.pishi.ifoxy.data.SettingsStore
import com.pishi.ifoxy.data.orderInetAddresses
import com.pishi.ifoxy.data.preferredProbeError
import com.pishi.ifoxy.vpn.upstream.orderEdgeAddresses
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Test
import java.net.InetAddress

/**
 * v1.0.37 pure-logic pins: the IP version mode shaping shared by
 * every edge-resolution path, the control plane's InetAddress
 * form of the same shaping, the solver's CAPTCHA-error
 * preference, and the Custom DNS DoH URL derivation.
 */
class IpVersionAndCustomDnsTest {

    private val v4 = listOf("203.0.113.10", "203.0.113.11")
    private val v6 = listOf("2001:db8::10", "2001:db8::11")

    // --- orderEdgeAddresses: the five modes (B1) ---

    @Test
    fun `AUTO orders IPv4 before IPv6`() {
        assertEquals(
            v4 + v6,
            orderEdgeAddresses(v4, v6, SettingsStore.IpVersionMode.AUTO),
        )
    }

    @Test
    fun `DUAL_STACK keeps both families`() {
        assertEquals(
            v4 + v6,
            orderEdgeAddresses(v4, v6, SettingsStore.IpVersionMode.DUAL_STACK),
        )
    }

    @Test
    fun `IPV6_FIRST orders IPv6 before IPv4`() {
        assertEquals(
            v6 + v4,
            orderEdgeAddresses(v4, v6, SettingsStore.IpVersionMode.IPV6_FIRST),
        )
    }

    @Test
    fun `IPV4_ONLY drops every IPv6 address`() {
        assertEquals(
            v4,
            orderEdgeAddresses(v4, v6, SettingsStore.IpVersionMode.IPV4_ONLY),
        )
    }

    @Test
    fun `IPV6_ONLY drops every IPv4 address`() {
        assertEquals(
            v6,
            orderEdgeAddresses(v4, v6, SettingsStore.IpVersionMode.IPV6_ONLY),
        )
    }

    @Test
    fun `ordering tolerates a missing family`() {
        assertEquals(
            v6,
            orderEdgeAddresses(emptyList(), v6, SettingsStore.IpVersionMode.AUTO),
        )
        assertEquals(
            emptyList<String>(),
            orderEdgeAddresses(v4, emptyList(), SettingsStore.IpVersionMode.IPV6_ONLY),
        )
        assertEquals(
            emptyList<String>(),
            orderEdgeAddresses(emptyList(), emptyList(), SettingsStore.IpVersionMode.DUAL_STACK),
        )
    }

    // --- orderInetAddresses: control-plane form (B4) ---

    private fun addr(vararg bytes: Int): InetAddress =
        InetAddress.getByAddress(bytes.map { it.toByte() }.toByteArray())

    private val inetV4a = addr(203, 0, 113, 10)
    private val inetV4b = addr(203, 0, 113, 11)
    private val inetV6a = addr(0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10)
    private val inetV6b = addr(0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x11)
    private val mixed = listOf(inetV6a, inetV4a, inetV6b, inetV4b)

    @Test
    fun `AUTO and DUAL_STACK keep the system order untouched`() {
        assertEquals(mixed, orderInetAddresses(mixed, SettingsStore.IpVersionMode.AUTO))
        assertEquals(mixed, orderInetAddresses(mixed, SettingsStore.IpVersionMode.DUAL_STACK))
    }

    @Test
    fun `IPV6_FIRST moves IPv6 ahead keeping relative order`() {
        assertEquals(
            listOf(inetV6a, inetV6b, inetV4a, inetV4b),
            orderInetAddresses(mixed, SettingsStore.IpVersionMode.IPV6_FIRST),
        )
    }

    @Test
    fun `ONLY modes filter the other family out`() {
        assertEquals(
            listOf(inetV4a, inetV4b),
            orderInetAddresses(mixed, SettingsStore.IpVersionMode.IPV4_ONLY),
        )
        assertEquals(
            listOf(inetV6a, inetV6b),
            orderInetAddresses(mixed, SettingsStore.IpVersionMode.IPV6_ONLY),
        )
    }

    // --- preferredProbeError: CAPTCHA signal robustness (A3) ---

    @Test
    fun `a captured CAPTCHA is never overwritten by a later plain failure`() {
        val captcha = FastlyCaptchaException("captcha")
        val later = FastlyChallengeError("host did not serve a Fastly challenge page")
        assertSame(captcha, preferredProbeError(captcha, later))
    }

    @Test
    fun `a CAPTCHA replaces an earlier plain failure`() {
        val earlier = FastlyChallengeError("Error probing https://api.accounts.firefox.com")
        val captcha = FastlyCaptchaException("captcha")
        assertSame(captcha, preferredProbeError(earlier, captcha))
    }

    @Test
    fun `between plain failures the newest wins as before`() {
        val earlier = FastlyChallengeError("first")
        val later = FastlyChallengeError("second")
        assertSame(later, preferredProbeError(earlier, later))
        assertSame(later, preferredProbeError(null, later))
    }

    // --- Custom DNS URL derivation (C1) ---

    @Test
    fun `custom DNS IPv4 literal becomes a DoH URL`() {
        assertEquals(
            "https://1.1.1.1/dns-query",
            SettingsStore.dohUrlForIpLiteral("1.1.1.1"),
        )
        assertEquals(
            "https://192.0.2.53/dns-query",
            SettingsStore.dohUrlForIpLiteral("  192.0.2.53  "),
        )
    }

    @Test
    fun `custom DNS IPv6 literal is bracketed in the DoH URL`() {
        assertEquals(
            "https://[2606:4700:4700::1111]/dns-query",
            SettingsStore.dohUrlForIpLiteral("2606:4700:4700::1111"),
        )
        assertEquals(
            "https://[2001:4860:4860::8888]/dns-query",
            SettingsStore.dohUrlForIpLiteral("2001:4860:4860::8888"),
        )
    }

    @Test
    fun `custom DNS blank input derives no URL`() {
        assertNull(SettingsStore.dohUrlForIpLiteral(""))
        assertNull(SettingsStore.dohUrlForIpLiteral("   "))
    }
}
