package com.pishi.ifoxy

import com.pishi.ifoxy.data.FastlyBlockedException
import com.pishi.ifoxy.data.FxaApiError
import com.pishi.ifoxy.data.FxaRefreshFailure
import com.pishi.ifoxy.data.isBotProtectionBlock
import com.pishi.ifoxy.data.isPermanentRefreshRejection
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

    // Permanent-refresh classification (v1.0.33): the old rule treated
    // every 400/401/403 as permanent and erased the stored session, so
    // a transient WAF/rate-limit 403 signed the user out. Permanent now
    // requires FxA's own verdict: HTTP 401, or errno 110 at any status.

    @Test
    fun `a 400 without errno evidence is not a permanent refresh rejection`() {
        assertFalse(FxaApiError("Bad request", null, 400).isPermanentRefreshRejection())
        assertFalse(FxaApiError("Bad request", 109, 400).isPermanentRefreshRejection())
    }

    @Test
    fun `a 403 without errno evidence is not a permanent refresh rejection`() {
        assertFalse(FxaApiError("Forbidden", null, 403).isPermanentRefreshRejection())
    }

    @Test
    fun `a 400 with errno 110 is a permanent refresh rejection`() {
        assertTrue(FxaApiError("Invalid authentication token", 110, 400).isPermanentRefreshRejection())
    }

    @Test
    fun `a 403 with errno 110 is a permanent refresh rejection`() {
        assertTrue(FxaApiError("Invalid authentication token", 110, 403).isPermanentRefreshRejection())
    }

    @Test
    fun `a 401 is a permanent refresh rejection`() {
        assertTrue(FxaApiError("Unauthorized", null, 401).isPermanentRefreshRejection())
    }
}
