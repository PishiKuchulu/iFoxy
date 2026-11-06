package com.pishi.ifoxy

import com.pishi.ifoxy.ui.screens.apiOriginOf
import com.pishi.ifoxy.ui.screens.isBlockedLikeExchange
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Regression tests for the 2026-11-06 on-device report: the browser
 * sign-in completed, but the in-page token exchange itself was
 * blocked (HTTP 406) on a flagged network, so sign-in failed even
 * though the whole point of the in-page route was to ride the
 * browser's trust. The recovery flow (retry with cookies, then let
 * the WebView clear the challenge on the API host) keys off these
 * two helpers: a response must be classified as a bot-protection
 * block, and the API origin must be derived exactly.
 */
class InPageExchangeClearanceTest {

    @Test
    fun `http 406 is a bot protection block`() {
        assertTrue(isBlockedLikeExchange(status = 406, hasTokenJson = false))
    }

    @Test
    fun `http 200 without token json is a challenge interstitial`() {
        assertTrue(isBlockedLikeExchange(status = 200, hasTokenJson = false))
    }

    @Test
    fun `http 200 with token json is a real answer`() {
        assertFalse(isBlockedLikeExchange(status = 200, hasTokenJson = true))
    }

    @Test
    fun `fxA rejections and transport failures are not blocks`() {
        assertFalse(isBlockedLikeExchange(status = 400, hasTokenJson = false))
        assertFalse(isBlockedLikeExchange(status = 401, hasTokenJson = false))
        assertFalse(isBlockedLikeExchange(status = -1, hasTokenJson = false))
        assertFalse(isBlockedLikeExchange(status = 0, hasTokenJson = false))
    }

    @Test
    fun `api origin comes from the token url`() {
        assertEquals(
            "https://api.accounts.firefox.com/",
            apiOriginOf("https://api.accounts.firefox.com/v1/oauth/token"),
        )
    }

    @Test
    fun `api origin keeps an explicit port`() {
        assertEquals(
            "https://example.com:8443/",
            apiOriginOf("https://example.com:8443/v1/oauth/token"),
        )
    }

    @Test
    fun `api origin rejects unparseable urls`() {
        assertNull(apiOriginOf("not a url"))
        assertNull(apiOriginOf("/relative/path"))
    }
}
