package com.pishi.ifoxy

import com.pishi.ifoxy.ui.screens.UnconfirmedFailureAction
import com.pishi.ifoxy.ui.screens.unconfirmedFailureAction
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * v1.0.38: the email-confirmation wait's retry discipline. The
 * on-device defect was that an "Unconfirmed session" verdict
 * (FxA errno 104 — Mozilla emailed a confirmation code) tore the
 * browser screen down, destroying the only surface where the
 * code could be entered. The fix keeps the browser open in a
 * waiting mode; these tests pin what each subsequent unconfirmed
 * verdict does: enter the mode once, never loop on the mode's
 * single automatic retry, and let manual Continue taps keep the
 * mode up.
 */
class UnconfirmedFailureActionTest {

    @Test
    fun `a first unconfirmed verdict enters the waiting mode`() {
        assertEquals(
            UnconfirmedFailureAction.ENTER_WAITING_MODE,
            unconfirmedFailureAction(wasWaitingModeRetry = false, retryWasManual = false),
        )
        assertEquals(
            UnconfirmedFailureAction.ENTER_WAITING_MODE,
            unconfirmedFailureAction(wasWaitingModeRetry = false, retryWasManual = true),
        )
    }

    @Test
    fun `a failed automatic retry falls back terminally instead of looping`() {
        assertEquals(
            UnconfirmedFailureAction.TERMINAL_FALLBACK,
            unconfirmedFailureAction(wasWaitingModeRetry = true, retryWasManual = false),
        )
    }

    @Test
    fun `a failed manual retry stays in the waiting mode`() {
        assertEquals(
            UnconfirmedFailureAction.STAY_IN_WAITING_MODE,
            unconfirmedFailureAction(wasWaitingModeRetry = true, retryWasManual = true),
        )
    }
}
