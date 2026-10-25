package com.pishi.ifoxy

import com.pishi.ifoxy.data.InMemorySharedPreferences
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Unit tests for the session-only fallback store used when the
 * encrypted store cannot be opened (external review, P1, second
 * wave). Pure in-memory behaviour — no Android runtime needed.
 */
class InMemoryPrefsTest {

    @Test
    fun putAndGetRoundTripsAllTypes() {
        val prefs = InMemorySharedPreferences()
        prefs.edit()
            .putString("s", "hello")
            .putInt("i", 42)
            .putLong("l", 123456789L)
            .putFloat("f", 1.5f)
            .putBoolean("b", true)
            .putStringSet("set", setOf("a", "b"))
            .commit()
        assertEquals("hello", prefs.getString("s", null))
        assertEquals(42, prefs.getInt("i", 0))
        assertEquals(123456789L, prefs.getLong("l", 0L))
        assertEquals(1.5f, prefs.getFloat("f", 0f))
        assertTrue(prefs.getBoolean("b", false))
        assertEquals(setOf("a", "b"), prefs.getStringSet("set", null))
        assertTrue(prefs.contains("s"))
    }

    @Test
    fun defaultsReturnedForMissingKeys() {
        val prefs = InMemorySharedPreferences()
        assertNull(prefs.getString("nope", null))
        assertEquals("dflt", prefs.getString("nope", "dflt"))
        assertEquals(7, prefs.getInt("nope", 7))
        assertFalse(prefs.getBoolean("nope", false))
        assertFalse(prefs.contains("nope"))
    }

    @Test
    fun removeAndClearDropKeys() {
        val prefs = InMemorySharedPreferences()
        prefs.edit().putString("a", "1").putString("b", "2").commit()
        prefs.edit().remove("a").commit()
        assertFalse(prefs.contains("a"))
        assertTrue(prefs.contains("b"))
        prefs.edit().clear().commit()
        assertFalse(prefs.contains("b"))
        assertTrue(prefs.getAll().isEmpty())
    }

    @Test
    fun nullValueRemovesKey() {
        val prefs = InMemorySharedPreferences()
        prefs.edit().putString("k", "v").commit()
        prefs.edit().putString("k", null).commit()
        assertFalse(prefs.contains("k"))
        assertNull(prefs.getString("k", null))
    }

    @Test
    fun returnedStringSetIsACopy() {
        val prefs = InMemorySharedPreferences()
        prefs.edit().putStringSet("set", setOf("x")).commit()
        val first = prefs.getStringSet("set", null) as MutableSet<String>
        first.add("y")
        assertEquals(setOf("x"), prefs.getStringSet("set", null))
    }

    @Test
    fun applyPersistsLikeCommit() {
        val prefs = InMemorySharedPreferences()
        prefs.edit().putString("k", "v").apply()
        assertEquals("v", prefs.getString("k", null))
    }

    @Test
    fun commitAlwaysReturnsTrue() {
        val prefs = InMemorySharedPreferences()
        assertTrue(prefs.edit().putString("k", "v").commit())
    }
}
