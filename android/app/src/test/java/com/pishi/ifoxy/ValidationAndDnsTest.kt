package com.pishi.ifoxy

import com.pishi.ifoxy.data.SettingsStore
import com.pishi.ifoxy.vpn.tun.HevSocks5TunnelConfig
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** TST-FX-11: input validators and the fake-DNS range check. */
class ValidationAndDnsTest {

    @Test
    fun fakeDnsRange_isExactly100_64_10() {
        assertTrue(HevSocks5TunnelConfig.isFakeDnsAddress("100.64.0.1"))
        assertTrue(HevSocks5TunnelConfig.isFakeDnsAddress("100.127.255.254"))
        assertFalse(HevSocks5TunnelConfig.isFakeDnsAddress("100.128.0.1"))
        assertFalse(HevSocks5TunnelConfig.isFakeDnsAddress("100.63.255.255"))
        assertFalse(HevSocks5TunnelConfig.isFakeDnsAddress("8.8.8.8"))
        assertFalse(HevSocks5TunnelConfig.isFakeDnsAddress("example.com"))
        assertFalse(HevSocks5TunnelConfig.isFakeDnsAddress("100.64.0.999"))
        assertFalse(HevSocks5TunnelConfig.isFakeDnsAddress(""))
    }

    @Test
    fun hostnameValidation() {
        assertTrue(SettingsStore.isValidHostname("example.com"))
        assertTrue(SettingsStore.isValidHostname("vpn-1.example.co.uk"))
        assertFalse(SettingsStore.isValidHostname("localhost"))
        assertFalse(SettingsStore.isValidHostname("-bad.example.com"))
        assertFalse(SettingsStore.isValidHostname("bad-.example.com"))
        assertFalse(SettingsStore.isValidHostname("exa mple.com"))
        assertFalse(SettingsStore.isValidHostname("1.2.3.4"))
        assertFalse(SettingsStore.isValidHostname(""))
    }

    @Test
    fun dohUrlValidation_requiresHttpsAndHost() {
        assertTrue(SettingsStore.isValidDohUrl("https://1.1.1.1/dns-query"))
        assertTrue(SettingsStore.isValidDohUrl("https://dns.example.com/dns-query"))
        assertFalse(SettingsStore.isValidDohUrl("http://1.1.1.1/dns-query"))
        assertFalse(SettingsStore.isValidDohUrl("https://"))
        assertFalse(SettingsStore.isValidDohUrl("not a url"))
    }
}
