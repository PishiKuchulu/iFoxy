package com.pishi.ifoxy

import com.pishi.ifoxy.data.hkdf
import com.pishi.ifoxy.data.pbkdf2HmacSha256
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * TST-FX-11: the FxA login derives all of its key material with hand-rolled
 * PBKDF2/HKDF (FxaAuthRepository). These known-answer tests pin that math to
 * published vectors so a future refactor cannot silently corrupt logins —
 * or, worse, weaken the derived credentials.
 */
class FxaCryptoTest {

    private fun ByteArray.hex(): String = joinToString("") { "%02x".format(it) }

    @Test
    fun pbkdf2_matchesPublishedVectors() {
        val password = "password".toByteArray(Charsets.UTF_8)
        val salt = "salt".toByteArray(Charsets.UTF_8)
        assertEquals(
            "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b",
            pbkdf2HmacSha256(password, salt, 1, 32).hex(),
        )
        assertEquals(
            "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43",
            pbkdf2HmacSha256(password, salt, 2, 32).hex(),
        )
        assertEquals(
            "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a",
            pbkdf2HmacSha256(password, salt, 4096, 32).hex(),
        )
    }

    @Test
    fun hkdf_zeroSalt_emptyInfo_knownAnswer() {
        // Reference value computed with an independent RFC 5869 implementation.
        val ikm = ByteArray(22) { 0x0b }
        assertEquals(
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d",
            hkdf(ikm, "", 32).hex(),
        )
    }

    @Test
    fun hkdf_sessionTokenShape_knownAnswer() {
        // Same shape as deriveHawkCredentials: 32-byte IKM, picl sessionToken
        // info string, 64-byte output (token id || HMAC key).
        val ikm = ByteArray(32) { 0xAA.toByte() }
        assertEquals(
            "87deb686c1022188e4b06c54027aa12759f425f8f95fcd78585b83a62fe563d8" +
                "e58630b6718a9ba08c5a94abfa94a04c1db5ea4b82f5f2be28ee83639cf5c1b7",
            hkdf(ikm, "identity.mozilla.com/picl/v1/sessionToken", 64).hex(),
        )
    }
}
