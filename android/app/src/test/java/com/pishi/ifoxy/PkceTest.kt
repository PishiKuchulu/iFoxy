package com.pishi.ifoxy

import com.pishi.ifoxy.data.pkceChallengeS256
import com.pishi.ifoxy.data.randomBase64Url
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The PKCE values sent to Mozilla's /oauth/authorization and /token
 * endpoints. The S256 challenge is pinned to the RFC 7636 Appendix B
 * vector, so a wrong encoding (padding, or '+' and '/' where '-' and '_'
 * belong) fails here instead of showing up as an opaque sign-in error.
 */
class PkceTest {

    @Test
    fun s256Challenge_matchesRfc7636AppendixB() {
        assertEquals(
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            pkceChallengeS256("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
        )
    }

    @Test
    fun verifierFromThirtyTwoBytes_isUrlSafeAndUnpadded() {
        val verifier = randomBase64Url(32)
        assertEquals(43, verifier.length)
        assertTrue(verifier.matches(Regex("[A-Za-z0-9_-]{43}")))
    }

    @Test
    fun consecutiveVerifiersDiffer() {
        assertTrue(randomBase64Url(32) != randomBase64Url(32))
    }
}
