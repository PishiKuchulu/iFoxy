package com.pishi.ifoxy

import com.pishi.ifoxy.util.AppUpdateChecker
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException

/**
 * Regression tests for the 1.0.28 on-device report: a phone on 1.0.27
 * showed "You're up to date" while v1.0.28 was live, because an HTTP
 * error from the releases API (the unauthenticated rate limit, HTTP
 * 403, routinely hit from shared VPN egress IPs) was treated exactly
 * like "no newer release". An error status must throw so the check
 * surfaces as FAILED, never as up to date.
 */
class AppUpdateHttpStatusTest {

    @Test
    fun `rate limited response throws with its status code`() {
        val error = assertThrows(IOException::class.java) {
            AppUpdateChecker.ensureSuccessful(403)
        }
        assertTrue(error.message!!.contains("403"))
    }

    @Test
    fun `server error throws instead of reading as no update`() {
        assertThrows(IOException::class.java) {
            AppUpdateChecker.ensureSuccessful(500)
        }
    }

    @Test
    fun `successful response does not throw`() {
        AppUpdateChecker.ensureSuccessful(200)
    }
}
