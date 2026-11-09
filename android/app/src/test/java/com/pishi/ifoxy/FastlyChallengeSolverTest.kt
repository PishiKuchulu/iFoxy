package com.pishi.ifoxy

import com.pishi.ifoxy.data.FastlyChallengeError
import com.pishi.ifoxy.data.FastlyChallengeSolver
import com.pishi.ifoxy.data.SimpleCookieJar
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Regression tests for the Fastly challenge solver, upgraded in
 * v1.0.34 to upstream FoxyVPN v2.0.2's design. The old solver's
 * init() parser was a single regex (init\((\[[^\]]*\]), ...)): it
 * stopped the challenge list at the first ']' anywhere — including
 * one inside a nested array in a challenge's data — and could not
 * validate that the init() call it read belongs to the challenge
 * prefix the page actually served. Fixtures are shaped like the
 * real payloads (the /_fs-ch-1T1wmsGaOgGaSxcX prefix is the one in
 * the 2026-11-09 on-device log); upstream ships no test fixtures.
 */
class FastlyChallengeSolverTest {

    private val solver = FastlyChallengeSolver(SimpleCookieJar())

    // --- challenge-page detection ---

    @Test
    fun `a fastly client challenge page is detected`() {
        val page = """
            <html><head><title>Client Challenge</title>
            <script src="/_fs-ch-1T1wmsGaOgGaSxcX/script.js?reload=true"></script>
            </head><body>Please wait while we verify your browser.</body></html>
        """.trimIndent()
        assertTrue(solver.isChallengePage(page))
    }

    @Test
    fun `a post-back reference also marks a challenge page`() {
        val page = """{"_fs":"/_fs-ch-1T1wmsGaOgGaSxcX/fst-post-back"}"""
        assertTrue(solver.isChallengePage(page))
    }

    @Test
    fun `ordinary responses are not challenge pages`() {
        assertFalse(solver.isChallengePage("""{"access_token":"abc"}"""))
        assertFalse(solver.isChallengePage(""))
        // A bare prefix mention without any challenge marker is not enough.
        assertFalse(solver.isChallengePage("see /_fs-ch-abc123 for details"))
    }

    // --- init() parsing ---

    @Test
    fun `init parses with the page prefix and nested challenge data`() {
        // The clientmetrics data carries a nested array: the old
        // regex parser cut the challenge list at its inner ']'.
        val script = """
            var _fs_done = false;
            init([{"ty":"pow","data":{"base":"ifoxy-v1034-pow-fixture","hash":"c50a2ad6ae617b944e35df0dfda0c94cfa61be097656cf015a307675e625e86f","hmac":"9f2c","expires":"1730000000"}},{"ty":"clientmetrics","data":{"flags":[1,2]}}], "dGVzdA.token-abc", "/_fs-ch-1T1wmsGaOgGaSxcX");
        """.trimIndent()
        val (challenges, token) = solver.parseChallengeInit(script, "/_fs-ch-1T1wmsGaOgGaSxcX")
        assertEquals("dGVzdA.token-abc", token)
        assertEquals(2, challenges.length())
        assertEquals("pow", challenges.getJSONObject(0).optString("ty"))
        assertEquals(
            "c50a2ad6ae617b944e35df0dfda0c94cfa61be097656cf015a307675e625e86f",
            challenges.getJSONObject(0).getJSONObject("data").optString("hash"),
        )
        assertEquals("clientmetrics", challenges.getJSONObject(1).optString("ty"))
    }

    @Test
    fun `init for a different prefix is skipped`() {
        // A decoy init() for another challenge id appears AFTER the
        // real one (candidates are tried newest-first): the prefix
        // check must reject it and fall through to the real call.
        val script = """
            init([{"ty":"pat","data":{}}], "real-token", "/_fs-ch-1T1wmsGaOgGaSxcX");
            init([{"ty":"pat","data":{}}], "decoy-token", "/_fs-ch-OTHER99999");
        """.trimIndent()
        val (challenges, token) = solver.parseChallengeInit(script, "/_fs-ch-1T1wmsGaOgGaSxcX")
        assertEquals("real-token", token)
        assertEquals(1, challenges.length())
    }

    @Test
    fun `the two argument legacy init form still parses`() {
        val script = """init([{"ty":"pat","data":{}}], "legacy-token");"""
        val (challenges, token) = solver.parseChallengeInit(script)
        assertEquals("legacy-token", token)
        assertEquals("pat", challenges.getJSONObject(0).optString("ty"))
    }

    @Test
    fun `a script without a usable init call is a hard failure`() {
        assertThrows(FastlyChallengeError::class.java) {
            solver.parseChallengeInit("var x = 1; // no challenge here", "/_fs-ch-1T1wmsGaOgGaSxcX")
        }
    }

    // --- proof of work ---

    @Test
    fun `proof of work finds the two character suffix`() {
        // Known-answer vector: SHA-256(base + "Q7") equals the hash.
        assertEquals(
            "Q7",
            solver.solvePow(
                "ifoxy-v1034-pow-fixture",
                "c50a2ad6ae617b944e35df0dfda0c94cfa61be097656cf015a307675e625e86f",
            ),
        )
    }

    @Test
    fun `proof of work rejects malformed targets`() {
        assertNull(solver.solvePow("base", "not-hex"))
        // 16 bytes is not a SHA-256 digest.
        assertNull(solver.solvePow("base", "00".repeat(16)))
    }

    // --- solver working jar (v1.0.35) ---

    @Test
    fun `the solver working jar starts empty even when the shared jar holds cookies`() {
        // Upstream parity, and the v1.0.34 on-device failure: a
        // seeded working jar made the next solve's probes present
        // the freshly earned clearance, so they were served plain
        // pages and the solve aborted with "host did not serve a
        // Fastly challenge page".
        val sharedJar = SimpleCookieJar()
        sharedJar.set("clearance", "secret-value", "api.accounts.firefox.com")
        val solverWithSharedCookies = FastlyChallengeSolver(sharedJar)
        assertTrue(solverWithSharedCookies.newSolverJar().snapshotAll().isEmpty())
    }
}
