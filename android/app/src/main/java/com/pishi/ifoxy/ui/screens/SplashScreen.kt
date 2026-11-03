package com.pishi.ifoxy.ui.screens

import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.pishi.ifoxy.R
import com.pishi.ifoxy.data.FxaAuthRepository
import com.pishi.ifoxy.data.SessionStatus
import com.pishi.ifoxy.ui.components.RippleDotsLoader
import kotlinx.coroutines.delay
import kotlinx.coroutines.withTimeoutOrNull

private const val SESSION_RESTORE_TIMEOUT_MS = 8_000L

@Composable
fun SplashScreen(
    authRepository: FxaAuthRepository,
    onSignedIn: () -> Unit,
    onNeedsLogin: () -> Unit,
) {
    var showStillWorking by remember { mutableStateOf(false) }
    LaunchedEffect(Unit) {
        delay(3_000)
        showStillWorking = true
    }

    LaunchedEffect(Unit) {
        delay(500)
        val status = withTimeoutOrNull(SESSION_RESTORE_TIMEOUT_MS) {
            authRepository.restoreSession()
        } ?: SessionStatus.UNREACHABLE

        when (status) {
            SessionStatus.ACTIVE -> onSignedIn()
            SessionStatus.UNREACHABLE -> onSignedIn()
            SessionStatus.NEEDS_LOGIN -> onNeedsLogin()
        }
    }

    Box(
        Modifier
            .fillMaxSize()
            .background(MaterialTheme.colorScheme.background),
        contentAlignment = Alignment.Center,
    ) {
        Column(
            horizontalAlignment = Alignment.CenterHorizontally,
            modifier = Modifier.semantics {
                liveRegion = LiveRegionMode.Polite
                contentDescription = "Loading"
            },
        ) {
            Image(
                // Raster copy of the launcher icon: R.mipmap.ic_launcher
                // resolves to the adaptive-icon XML on API 26+, which
                // painterResource cannot load (crashes the splash).
                painter = painterResource(R.drawable.app_icon),
                contentDescription = null,
                modifier = Modifier
                    .size(96.dp)
                    .clip(RoundedCornerShape(24.dp)),
            )
            Spacer(Modifier.height(36.dp))
            // Ripple-dots loader, inked with the theme's on-background
            // color so it tracks the resolved splash background.
            RippleDotsLoader(ink = MaterialTheme.colorScheme.onBackground, size = 72.dp)
            if (showStillWorking) {
                Spacer(Modifier.height(24.dp))
                Text(
                    "Still working…",
                    color = MaterialTheme.colorScheme.onBackground.copy(alpha = 0.7f),
                    fontSize = 13.sp,
                )
            }
        }
    }
}
