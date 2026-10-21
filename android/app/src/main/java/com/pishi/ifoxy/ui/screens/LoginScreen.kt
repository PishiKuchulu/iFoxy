package com.pishi.ifoxy.ui.screens

import android.content.Intent
import android.net.Uri
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.PowerSettingsNew
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TextField
import androidx.compose.material3.TextFieldDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.pishi.ifoxy.data.FxaAuthRepository
import com.pishi.ifoxy.ui.components.WorldMapLayer
import com.pishi.ifoxy.ui.theme.IFoxyBgDark
import com.pishi.ifoxy.ui.theme.IFoxyCardDark
import com.pishi.ifoxy.ui.theme.IFoxyErrorOnDark
import com.pishi.ifoxy.ui.theme.IFoxyInk
import com.pishi.ifoxy.ui.theme.IFoxyNeonOrange
import com.pishi.ifoxy.ui.theme.IFoxyYellow
import com.pishi.ifoxy.ui.theme.PoppinsFamily
import kotlinx.coroutines.launch

private const val FXA_RESET_PASSWORD_URL = "https://accounts.firefox.com/reset_password"

/**
 * Sign in, per the Penpot design (04): dark brand screen, glowing orange
 * power mark, Firefox-account form. Auth flow, input sanitising and the
 * SEC-FX-01 secret handling are unchanged.
 */
@Composable
fun LoginScreen(
    authRepository: FxaAuthRepository,
    onSignedIn: () -> Unit,
) {
    var email by rememberSaveable { mutableStateOf("") }
    // SEC-FX-01: secrets must never enter SavedState (it can be persisted to
    // disk by the system). Password and 2FA code live in memory only.
    var password by remember { mutableStateOf("") }
    var code by remember { mutableStateOf("") }
    var awaitingTwoFactor by rememberSaveable { mutableStateOf(authRepository.pendingSessionToken != null) }
    var isLoading by remember { mutableStateOf(false) }
    var errorMessage by rememberSaveable { mutableStateOf<String?>(null) }
    val scope = rememberCoroutineScope()
    val focusManager = LocalFocusManager.current
    val context = LocalContext.current

    BackHandler(enabled = awaitingTwoFactor) {
        authRepository.clearPendingSession()
        awaitingTwoFactor = false
        errorMessage = null
        code = ""
    }

    fun doSubmitLogin() {
        val cleanEmail = FxaAuthRepository.normalizeEmail(email)
        if (cleanEmail.isBlank() || password.isBlank() || isLoading) return
        errorMessage = null
        isLoading = true
        scope.launch {
            val result = authRepository.startLogin(cleanEmail, password)
            isLoading = false
            result.onSuccess { needsVerification ->
                if (needsVerification) awaitingTwoFactor = true else onSignedIn()
            }.onFailure { errorMessage = it.message ?: "Sign-in failed" }
        }
    }

    fun doSubmitTwoFactor() {
        val cleanCode = FxaAuthRepository.sanitizeCode(code)
        if (cleanCode.isBlank() || isLoading) return
        errorMessage = null
        isLoading = true
        scope.launch {
            val result = authRepository.submitTwoFactorCode(cleanCode)
            isLoading = false
            result.onSuccess { onSignedIn() }
                .onFailure {
                    errorMessage = it.message ?: "Verification failed"
                    if (authRepository.pendingSessionToken == null) {
                        awaitingTwoFactor = false
                    }
                }
        }
    }

    val fieldColors = TextFieldDefaults.colors(
        focusedContainerColor = IFoxyCardDark,
        unfocusedContainerColor = IFoxyCardDark,
        disabledContainerColor = IFoxyCardDark,
        focusedIndicatorColor = Color.Transparent,
        unfocusedIndicatorColor = Color.Transparent,
        disabledIndicatorColor = Color.Transparent,
        focusedTextColor = Color.White,
        unfocusedTextColor = Color.White,
        cursorColor = IFoxyYellow,
        focusedLabelColor = Color.White.copy(alpha = 0.6f),
        unfocusedLabelColor = Color.White.copy(alpha = 0.45f),
    )
    val fieldShape = RoundedCornerShape(16.dp)

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(IFoxyBgDark)
            .imePadding(),
        contentAlignment = Alignment.TopCenter,
    ) {
        // Faint static world map behind the header (design 04).
        WorldMapLayer(
            color = Color.White.copy(alpha = 0.045f),
            driftMillis = null,
            modifier = Modifier
                .fillMaxWidth()
                .height(360.dp),
        )

        Column(
            modifier = Modifier
                .widthIn(max = 520.dp)
                .fillMaxWidth()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 24.dp),
            verticalArrangement = Arrangement.Top,
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Spacer(Modifier.height(72.dp))

            // Glowing orange power mark.
            Box(contentAlignment = Alignment.Center) {
                Box(
                    modifier = Modifier
                        .size(120.dp)
                        .clip(CircleShape)
                        .background(
                            Brush.radialGradient(
                                colors = listOf(
                                    IFoxyNeonOrange.copy(alpha = 0.4f),
                                    IFoxyNeonOrange.copy(alpha = 0f),
                                ),
                            ),
                        ),
                )
                Box(
                    modifier = Modifier
                        .size(72.dp)
                        .clip(CircleShape)
                        .background(IFoxyNeonOrange),
                    contentAlignment = Alignment.Center,
                ) {
                    Icon(
                        imageVector = Icons.Filled.PowerSettingsNew,
                        contentDescription = null,
                        tint = Color.White,
                        modifier = Modifier.size(36.dp),
                    )
                }
            }

            Spacer(Modifier.height(22.dp))
            Text(
                "Welcome to iFoxy",
                style = TextStyle(
                    fontFamily = PoppinsFamily,
                    fontWeight = FontWeight.Bold,
                    fontSize = 24.sp,
                ),
                color = Color.White,
            )
            Spacer(Modifier.height(6.dp))
            Text(
                "Sign in with your Firefox account",
                style = TextStyle(
                    fontFamily = PoppinsFamily,
                    fontWeight = FontWeight.Normal,
                    fontSize = 14.sp,
                ),
                color = Color.White.copy(alpha = 0.6f),
            )
            Spacer(Modifier.height(30.dp))

            if (!awaitingTwoFactor) {
                TextField(
                    value = email,
                    onValueChange = {
                        email = it.replace(Regex("[\\p{Z}\\u200B-\\u200D\\uFEFF\\u00A0\\s]+"), "").lowercase()
                    },
                    label = { Text("Email") },
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(
                        keyboardType = KeyboardType.Email,
                        imeAction = ImeAction.Next,
                        autoCorrectEnabled = false,
                    ),
                    keyboardActions = KeyboardActions(
                        onNext = { focusManager.moveFocus(androidx.compose.ui.focus.FocusDirection.Down) }
                    ),
                    colors = fieldColors,
                    shape = fieldShape,
                    modifier = Modifier.fillMaxWidth(),
                )
                Spacer(Modifier.height(12.dp))
                TextField(
                    value = password,
                    onValueChange = {
                        password = it.replace(Regex("[\\u200B-\\u200D\\uFEFF]"), "")
                    },
                    label = { Text("Password") },
                    singleLine = true,
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(
                        keyboardType = KeyboardType.Password,
                        imeAction = ImeAction.Done,
                    ),
                    keyboardActions = KeyboardActions(
                        onDone = {
                            focusManager.clearFocus()
                            doSubmitLogin()
                        }
                    ),
                    colors = fieldColors,
                    shape = fieldShape,
                    modifier = Modifier.fillMaxWidth(),
                )
                Spacer(Modifier.height(20.dp))
                Button(
                    onClick = {
                        focusManager.clearFocus()
                        doSubmitLogin()
                    },
                    enabled = !isLoading && email.isNotBlank() && password.isNotBlank(),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = IFoxyYellow,
                        contentColor = IFoxyInk,
                        disabledContainerColor = IFoxyYellow.copy(alpha = 0.4f),
                        disabledContentColor = IFoxyInk.copy(alpha = 0.6f),
                    ),
                    shape = RoundedCornerShape(27.dp),
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(54.dp),
                ) {
                    if (isLoading) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(20.dp),
                            strokeWidth = 2.dp,
                            color = IFoxyInk,
                        )
                    } else {
                        Text(
                            "Sign In",
                            style = TextStyle(
                                fontFamily = PoppinsFamily,
                                fontWeight = FontWeight.SemiBold,
                                fontSize = 15.5.sp,
                            ),
                        )
                    }
                }

                TextButton(
                    onClick = {
                        context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(FXA_RESET_PASSWORD_URL)))
                    },
                ) {
                    Text(
                        "Forgot password?",
                        style = TextStyle(
                            fontFamily = PoppinsFamily,
                            fontWeight = FontWeight.Medium,
                            fontSize = 13.5.sp,
                        ),
                        color = IFoxyYellow,
                    )
                }
                Text(
                    "Two-factor authentication is supported",
                    style = TextStyle(
                        fontFamily = PoppinsFamily,
                        fontWeight = FontWeight.Normal,
                        fontSize = 12.sp,
                    ),
                    color = Color.White.copy(alpha = 0.4f),
                )
            } else {
                Text(
                    "Enter the confirmation code sent to your email",
                    style = TextStyle(
                        fontFamily = PoppinsFamily,
                        fontWeight = FontWeight.Medium,
                        fontSize = 15.sp,
                    ),
                    color = Color.White,
                    textAlign = TextAlign.Center,
                )
                Spacer(Modifier.height(14.dp))
                TextField(
                    value = code,
                    onValueChange = {
                        code = it.replace(Regex("[\\p{Z}\\u200B-\\u200D\\uFEFF\\u00A0\\s]+"), "")
                    },
                    label = { Text("Confirmation code") },
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(
                        keyboardType = KeyboardType.NumberPassword,
                        imeAction = ImeAction.Done,
                    ),
                    keyboardActions = KeyboardActions(
                        onDone = {
                            focusManager.clearFocus()
                            doSubmitTwoFactor()
                        }
                    ),
                    colors = fieldColors,
                    shape = fieldShape,
                    modifier = Modifier.fillMaxWidth(),
                )
                Spacer(Modifier.height(20.dp))
                Button(
                    onClick = {
                        focusManager.clearFocus()
                        doSubmitTwoFactor()
                    },
                    enabled = !isLoading && code.isNotBlank(),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = IFoxyYellow,
                        contentColor = IFoxyInk,
                        disabledContainerColor = IFoxyYellow.copy(alpha = 0.4f),
                        disabledContentColor = IFoxyInk.copy(alpha = 0.6f),
                    ),
                    shape = RoundedCornerShape(27.dp),
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(54.dp),
                ) {
                    if (isLoading) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(20.dp),
                            strokeWidth = 2.dp,
                            color = IFoxyInk,
                        )
                    } else {
                        Text(
                            "Verify",
                            style = TextStyle(
                                fontFamily = PoppinsFamily,
                                fontWeight = FontWeight.SemiBold,
                                fontSize = 15.5.sp,
                            ),
                        )
                    }
                }
            }

            errorMessage?.let {
                Spacer(Modifier.height(14.dp))
                Text(
                    text = it,
                    color = IFoxyErrorOnDark,
                    textAlign = TextAlign.Center,
                    style = TextStyle(
                        fontFamily = PoppinsFamily,
                        fontWeight = FontWeight.Medium,
                        fontSize = 13.sp,
                    ),
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 8.dp),
                )
            }
            Spacer(Modifier.height(32.dp))
        }
    }
}
