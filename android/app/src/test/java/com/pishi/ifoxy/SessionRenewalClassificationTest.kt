package com.pishi.ifoxy

import com.pishi.ifoxy.data.FastlyBlockedException
import com.pishi.ifoxy.data.FxaApiError
import com.pishi.ifoxy.data.FxaRefreshFailure
import com.pishi.ifoxy.data.isBotProtectionBlock
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Regression tests for the 2026-11-06 on-device log: the access token
 * had expired, the native renewal hit Mozilla's bot protection
 * (HTTP 406, challenge unsolvable on that network), and the connect
 * flow carried on with the dead token — Guardian 401, entitlement
 * activation 401, four attempts across three servers, all doomed.
 * A blocked renewal must be classified as such so the connect flow
 * can fail fast instead of treating it like a transient failure.
 */
class SessionRenewalClassificationTest {

    @Test
    fun `a bot protection block is detected directly`() {
        assertTrue(FastlyBlockedException("blocked").isBotProtectionBlock())
    }

    @Test
    fun `a bot protection block is detected through a wrapper`() {
        val wrapped = IllegalStateException("renewal failed", FastlyBlockedException("blocked"))
        assertTrue(wrapped.isBotProtectionBlock())
    }

    @Test
    fun `an fxA rejection is not a bot protection block`() {
        assertFalse(FxaApiError("Invalid refresh token", 122, 400).isBotProtectionBlock())
    }

    @Test
    fun `a plain transport failure is not a bot protection block`() {
        assertFalse(java.io.IOException("network unreachable").isBotProtectionBlock())
    }

    @Test
    fun `refresh failure carries the blocked flag only when set`() {
        assertFalse(FxaRefreshFailure("nope", permanent = false).blockedByBotProtection)
        assertTrue(
            FxaRefreshFailure(
                "blocked",
                permanent = false,
                blockedByBotProtection = true,
            ).blockedByBotProtection,
        )
    }
}
