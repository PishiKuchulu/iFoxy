package com.pishi.ifoxy

import com.pishi.ifoxy.data.StoredAccount
import com.pishi.ifoxy.data.selectNextAccount
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class AccountSelectionTest {

    private fun account(
        id: String,
        remaining: Long? = null,
        exhausted: Boolean = false,
        unlimited: Boolean = false,
    ) = StoredAccount(
        id = id,
        email = "$id@example.com",
        accessToken = "token-$id",
        quotaRemaining = remaining,
        exhausted = exhausted,
        isUnlimited = unlimited,
    )

    @Test
    fun `rotates to the next account in order`() {
        val accounts = listOf(account("a"), account("b"), account("c"))
        assertEquals("b", selectNextAccount(accounts, activeId = "a")?.id)
        assertEquals("a", selectNextAccount(accounts, activeId = "c")?.id)
    }

    @Test
    fun `skips exhausted and zero-quota accounts`() {
        val accounts = listOf(
            account("a"),
            account("b", exhausted = true),
            account("c", remaining = 0),
            account("d", remaining = 5),
        )
        assertEquals("d", selectNextAccount(accounts, activeId = "a")?.id)
    }

    @Test
    fun `unknown quota and unlimited accounts qualify`() {
        val accounts = listOf(
            account("a", remaining = 0, exhausted = true),
            account("b"),
            account("c", unlimited = true),
        )
        assertEquals("b", selectNextAccount(accounts, activeId = "a")?.id)
    }

    @Test
    fun `returns null when nothing viable remains`() {
        val accounts = listOf(
            account("a"),
            account("b", exhausted = true),
            account("c", remaining = 0),
        )
        assertNull(selectNextAccount(accounts, activeId = "a"))
        assertNull(selectNextAccount(emptyList(), activeId = null))
    }

    @Test
    fun `stored accounts survive a json round trip`() {
        val accounts = listOf(
            account("a", remaining = 1024, exhausted = false),
            account("b", remaining = null, exhausted = true, unlimited = true),
        )
        val roundTripped = Json.decodeFromString<List<StoredAccount>>(Json.encodeToString(accounts))
        assertEquals(accounts, roundTripped)
    }
}
