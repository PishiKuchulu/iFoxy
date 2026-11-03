package com.pishi.ifoxy.ui.screens

import android.app.Activity
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.view.WindowCompat
import com.pishi.ifoxy.data.ProxyStateStore
import com.pishi.ifoxy.data.RECOMMENDED_COUNTRY_CODE
import com.pishi.ifoxy.data.ServerListClient
import com.pishi.ifoxy.data.model.VpnCountry
import com.pishi.ifoxy.data.model.emojiFlag
import com.pishi.ifoxy.ui.theme.IFoxyBgDark
import com.pishi.ifoxy.ui.theme.IFoxyCardDark
import com.pishi.ifoxy.ui.theme.IFoxyErrorOnDark
import com.pishi.ifoxy.ui.theme.IFoxyYellow
import com.pishi.ifoxy.ui.theme.PoppinsFamily
import com.pishi.ifoxy.vpn.PingUtil
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext

private sealed class LocationRow {
    data class RecommendedRow(val country: VpnCountry) : LocationRow()
    data class CountryHeader(val country: VpnCountry) : LocationRow()
    data class CityRow(val country: VpnCountry, val cityIndex: Int) : LocationRow()
}

private enum class PingState { PENDING, DONE, FAILED }

private val Muted = Color.White.copy(alpha = 0.62f)
private val Faint = Color.White.copy(alpha = 0.6f)

/**
 * Choose location, per the Penpot design (03): dark brand screen,
 * Recommended card on top, then countries with their cities, a radio
 * marker on the selected city and live ping on the right. Data, caching
 * and ping behaviour are the app's existing ones.
 */
@Composable
fun ServerListScreen(
    serverListClient: ServerListClient,
    proxyStateStore: ProxyStateStore,
    onServerSelected: () -> Unit,
    onBack: () -> Unit,
) {
    var countries by remember { mutableStateOf<List<VpnCountry>>(emptyList()) }
    var isLoading by remember { mutableStateOf(true) }
    var errorMessage by remember { mutableStateOf<String?>(null) }
    // Row-tap failures ("no servers for this pick") get their own
    // transient banner: the full-screen error state below only exists
    // when the list is empty, so routing tap errors into errorMessage
    // made those taps silently do nothing.
    var tapError by remember { mutableStateOf<String?>(null) }
    var refreshFailed by remember { mutableStateOf(false) }
    var refreshAttempt by remember { mutableStateOf(0) }
    var searchQuery by remember { mutableStateOf("") }

    // This screen's background is always the dark brand color, but the
    // theme derives status-bar icon appearance from the app theme: in
    // the light theme it picks dark icons, which vanish on this dark
    // surface. Force light icons while composed and hand back the
    // theme-driven value (captured before overriding) on dispose.
    val view = LocalView.current
    DisposableEffect(view) {
        val controller = (view.context as? Activity)?.window
            ?.let { WindowCompat.getInsetsController(it, view) }
        val themeDrivenAppearance = controller?.isAppearanceLightStatusBars
        controller?.isAppearanceLightStatusBars = false
        onDispose {
            if (themeDrivenAppearance != null) {
                controller?.isAppearanceLightStatusBars = themeDrivenAppearance
            }
        }
    }

    val selectedState by proxyStateStore.selectedProxyFlow.collectAsState()

    val pingResults = remember { mutableStateMapOf<String, Int>() }
    val pingStates = remember { mutableStateMapOf<String, PingState>() }

    LaunchedEffect(tapError) {
        if (tapError != null) {
            delay(3_500)
            tapError = null
        }
    }

    LaunchedEffect(refreshAttempt) {
        if (refreshAttempt == 0) {
            val cached = withContext(Dispatchers.IO) { serverListClient.loadCachedCountries() }
            if (cached.isNotEmpty()) {
                countries = cached
                isLoading = false
            }
        } else {
            isLoading = countries.isEmpty()
            errorMessage = null
        }
        runCatching { serverListClient.fetchCountries() }
            .onSuccess { fresh ->
                countries = fresh
                errorMessage = null
                refreshFailed = false
            }
            .onFailure {
                if (countries.isEmpty()) {
                    errorMessage = it.message ?: "Failed to load server list"
                } else {
                    refreshFailed = true
                }
            }
        isLoading = false
    }

    val ordered = remember(countries) {
        countries.sortedWith(compareBy({ it.code != RECOMMENDED_COUNTRY_CODE }, { it.name }))
    }

    // Search filter: a country survives on its own name match (with all
    // its cities) or with only the cities whose names match. Selection
    // and candidates still resolve against the full `countries` list.
    val visibleCountries = remember(ordered, searchQuery) {
        val query = searchQuery.trim()
        if (query.isEmpty()) {
            ordered
        } else {
            ordered.mapNotNull { country ->
                when {
                    country.name.contains(query, ignoreCase = true) -> country
                    else -> {
                        val matchingCities = country.cities.filter {
                            it.name.contains(query, ignoreCase = true)
                        }
                        if (matchingCities.isEmpty()) {
                            null
                        } else {
                            country.copy(cities = matchingCities)
                        }
                    }
                }
            }
        }
    }

    val rows = remember(visibleCountries) {
        buildList {
            for (country in visibleCountries) {
                if (country.code == RECOMMENDED_COUNTRY_CODE) {
                    add(LocationRow.RecommendedRow(country))
                    continue
                }
                add(LocationRow.CountryHeader(country))
                country.cities.indices.forEach { index -> add(LocationRow.CityRow(country, index)) }
            }
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(IFoxyBgDark)
            .statusBarsPadding(),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        // Same 520.dp content cap Home/Login use (the dark background
        // stays full-bleed on the root column; only content is capped).
        Column(
            modifier = Modifier
                .widthIn(max = 520.dp)
                .fillMaxWidth()
                .fillMaxHeight(),
        ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 8.dp, vertical = 6.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            IconButton(onClick = onBack) {
                Icon(
                    imageVector = Icons.AutoMirrored.Filled.ArrowBack,
                    contentDescription = "Back",
                    tint = Color.White,
                )
            }
            Text(
                "Choose location",
                style = TextStyle(
                    fontFamily = PoppinsFamily,
                    fontWeight = FontWeight.SemiBold,
                    fontSize = 20.sp,
                ),
                color = Color.White,
            )
        }

        if (countries.isNotEmpty()) {
            BasicTextField(
                value = searchQuery,
                onValueChange = { searchQuery = it },
                singleLine = true,
                textStyle = TextStyle(
                    fontFamily = PoppinsFamily,
                    fontWeight = FontWeight.Normal,
                    fontSize = 14.sp,
                    color = Color.White,
                ),
                cursorBrush = SolidColor(IFoxyYellow),
                decorationBox = { innerTextField ->
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clip(RoundedCornerShape(14.dp))
                            .background(IFoxyCardDark)
                            .padding(horizontal = 14.dp, vertical = 12.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Icon(
                            imageVector = Icons.Filled.Search,
                            contentDescription = null,
                            tint = Muted,
                            modifier = Modifier.size(18.dp),
                        )
                        Spacer(Modifier.width(10.dp))
                        Box(Modifier.weight(1f)) {
                            if (searchQuery.isEmpty()) {
                                Text(
                                    "Search locations",
                                    style = TextStyle(
                                        fontFamily = PoppinsFamily,
                                        fontWeight = FontWeight.Normal,
                                        fontSize = 14.sp,
                                    ),
                                    color = Color.White.copy(alpha = 0.45f),
                                )
                            }
                            innerTextField()
                        }
                        if (searchQuery.isNotEmpty()) {
                            Icon(
                                imageVector = Icons.Filled.Close,
                                contentDescription = "Clear search",
                                tint = Muted,
                                modifier = Modifier
                                    .size(18.dp)
                                    .clickable { searchQuery = "" },
                            )
                        }
                    }
                },
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 20.dp, vertical = 4.dp),
            )
        }

        if (tapError != null) {
            Text(
                text = tapError.orEmpty(),
                color = IFoxyErrorOnDark,
                style = TextStyle(
                    fontFamily = PoppinsFamily,
                    fontWeight = FontWeight.Medium,
                    fontSize = 13.sp,
                ),
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 20.dp, vertical = 6.dp)
                    // The banner auto-dismisses after 3.5 s; assertive so
                    // TalkBack announces it before it is gone.
                    .semantics { liveRegion = LiveRegionMode.Assertive },
            )
        }

        Box(Modifier.fillMaxSize()) {
            when {
                isLoading -> CircularProgressIndicator(
                    color = IFoxyYellow,
                    modifier = Modifier.align(Alignment.Center),
                )
                errorMessage != null && countries.isEmpty() -> Column(
                    modifier = Modifier
                        .align(Alignment.Center)
                        .fillMaxWidth()
                        .padding(24.dp),
                    horizontalAlignment = Alignment.CenterHorizontally,
                ) {
                    Text(
                        text = errorMessage.orEmpty(),
                        textAlign = TextAlign.Center,
                        color = IFoxyErrorOnDark,
                        style = TextStyle(fontFamily = PoppinsFamily, fontSize = 14.sp),
                    )
                    Spacer(Modifier.height(12.dp))
                    TextButton(
                        onClick = { refreshAttempt++ },
                        modifier = Modifier.heightIn(min = 48.dp),
                    ) {
                        Text(
                            "Retry",
                            color = IFoxyYellow,
                            style = TextStyle(
                                fontFamily = PoppinsFamily,
                                fontWeight = FontWeight.SemiBold,
                                fontSize = 14.sp,
                            ),
                        )
                    }
                }
                rows.isEmpty() && countries.isNotEmpty() -> Text(
                    // The full list loaded fine; only the search filter
                    // matched nothing.
                    text = "No locations match your search",
                    textAlign = TextAlign.Center,
                    color = Muted,
                    style = TextStyle(
                        fontFamily = PoppinsFamily,
                        fontWeight = FontWeight.Normal,
                        fontSize = 14.sp,
                    ),
                    modifier = Modifier
                        .align(Alignment.Center)
                        .fillMaxWidth()
                        .padding(24.dp),
                )
                else -> LazyColumn(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(horizontal = 20.dp),
                ) {
                    if (refreshFailed) {
                        item(key = "stale-caption") {
                            Text(
                                "Couldn't refresh \u2014 showing saved list",
                                style = TextStyle(
                                    fontFamily = PoppinsFamily,
                                    fontWeight = FontWeight.Normal,
                                    fontSize = 12.sp,
                                ),
                                color = Faint,
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(vertical = 6.dp),
                            )
                        }
                    }
                    items(
                        rows,
                        key = { row ->
                            when (row) {
                                is LocationRow.RecommendedRow -> "recommended:${row.country.code}"
                                is LocationRow.CountryHeader -> "country:${row.country.code}"
                                is LocationRow.CityRow ->
                                    "city:${row.country.code}:${row.country.cities[row.cityIndex].code}"
                            }
                        },
                    ) { row ->
                        val selected = selectedState
                        when (row) {
                            is LocationRow.RecommendedRow -> {
                                val isSelected = row.country.code == selected?.countryCode
                                Row(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .padding(vertical = 6.dp)
                                        .clip(RoundedCornerShape(18.dp))
                                        .background(IFoxyCardDark)
                                        .clickable(role = Role.Button) {
                                            val candidates = ServerListClient.candidatesForCountry(countries, row.country.code)
                                            val chosen = candidates.randomOrNull()
                                            if (chosen != null) {
                                                proxyStateStore.save(chosen)
                                                onServerSelected()
                                            } else {
                                                tapError = "No available servers for ${row.country.name}"
                                            }
                                        }
                                        .padding(16.dp),
                                    verticalAlignment = Alignment.CenterVertically,
                                ) {
                                    RadioMarker(selected = isSelected)
                                    Spacer(Modifier.width(14.dp))
                                    Column(Modifier.weight(1f)) {
                                        Text(
                                            "Recommended",
                                            style = TextStyle(
                                                fontFamily = PoppinsFamily,
                                                fontWeight = FontWeight.SemiBold,
                                                fontSize = 15.5.sp,
                                            ),
                                            color = Color.White,
                                        )
                                        Spacer(Modifier.height(2.dp))
                                        Text(
                                            "Automatically chosen for the best performance",
                                            style = TextStyle(
                                                fontFamily = PoppinsFamily,
                                                fontWeight = FontWeight.Normal,
                                                fontSize = 12.sp,
                                            ),
                                            color = Muted,
                                        )
                                    }
                                    if (isSelected) {
                                        Box(
                                            modifier = Modifier
                                                .size(26.dp)
                                                .clip(CircleShape)
                                                .background(IFoxyYellow),
                                            contentAlignment = Alignment.Center,
                                        ) {
                                            Icon(
                                                imageVector = Icons.Filled.Check,
                                                contentDescription = "Selected",
                                                tint = IFoxyBgDark,
                                                modifier = Modifier.size(16.dp),
                                            )
                                        }
                                    }
                                }
                            }
                            is LocationRow.CountryHeader -> {
                                Row(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .padding(top = 18.dp, bottom = 4.dp),
                                    verticalAlignment = Alignment.CenterVertically,
                                ) {
                                    Text(text = row.country.emojiFlag, fontSize = 19.sp)
                                    Spacer(Modifier.width(10.dp))
                                    Text(
                                        row.country.name,
                                        style = TextStyle(
                                            fontFamily = PoppinsFamily,
                                            fontWeight = FontWeight.SemiBold,
                                            fontSize = 15.5.sp,
                                        ),
                                        color = Color.White,
                                        maxLines = 1,
                                        overflow = TextOverflow.Ellipsis,
                                    )
                                }
                            }
                            is LocationRow.CityRow -> {
                                val city = row.country.cities[row.cityIndex]
                                val isSelected = row.country.code == selected?.countryCode &&
                                    city.code == selected?.cityCode

                                val pingKey = "${row.country.code}:${city.code}"
                                val pingMs = pingResults[pingKey]
                                val pingState = pingStates[pingKey] ?: PingState.PENDING

                                LaunchedEffect(pingKey) {
                                    if (pingStates.containsKey(pingKey)) return@LaunchedEffect
                                    val target = city.servers.firstOrNull { !it.quarantined }
                                        ?.let { ServerListClient.defaultConnectTarget(it) }
                                    if (target == null) {
                                        pingStates[pingKey] = PingState.FAILED
                                        return@LaunchedEffect
                                    }
                                    val result = PingUtil.measureTcpLatencyMs(target.first, target.second)
                                    if (result != null) {
                                        pingResults[pingKey] = result
                                        pingStates[pingKey] = PingState.DONE
                                    } else {
                                        pingStates[pingKey] = PingState.FAILED
                                    }
                                }

                                Row(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .heightIn(min = 48.dp)
                                        .selectable(
                                            selected = isSelected,
                                            role = Role.RadioButton,
                                        ) {
                                            val candidates = ServerListClient.candidatesForCity(countries, row.country.code, city.code)
                                            val chosen = candidates.randomOrNull()
                                            if (chosen != null) {
                                                proxyStateStore.save(chosen)
                                                onServerSelected()
                                            } else {
                                                tapError = "No available servers in ${city.name.ifBlank { city.code }}"
                                            }
                                        }
                                        .padding(start = 32.dp, top = 9.dp, bottom = 9.dp),
                                    verticalAlignment = Alignment.CenterVertically,
                                ) {
                                    RadioMarker(selected = isSelected)
                                    Spacer(Modifier.width(12.dp))
                                    Text(
                                        city.name.ifBlank { city.code },
                                        style = TextStyle(
                                            fontFamily = PoppinsFamily,
                                            fontWeight = if (isSelected) FontWeight.SemiBold else FontWeight.Normal,
                                            fontSize = 14.5.sp,
                                        ),
                                        color = if (isSelected) Color.White else Color.White.copy(alpha = 0.82f),
                                        maxLines = 1,
                                        overflow = TextOverflow.Ellipsis,
                                    )
                                    Spacer(Modifier.weight(1f))
                                    Text(
                                        text = when {
                                            pingMs != null -> "$pingMs ms"
                                            pingState == PingState.FAILED -> "unavailable"
                                            else -> "pinging\u2026"
                                        },
                                        style = TextStyle(
                                            fontFamily = PoppinsFamily,
                                            fontWeight = FontWeight.Normal,
                                            fontSize = 12.5.sp,
                                        ),
                                        color = Muted,
                                    )
                                }
                            }
                        }
                    }

                    item(key = "footer") {
                        Spacer(Modifier.height(28.dp))
                        Text(
                            "Servers provided by the Mozilla Guardian network",
                            textAlign = TextAlign.Center,
                            style = TextStyle(
                                fontFamily = PoppinsFamily,
                                fontWeight = FontWeight.Normal,
                                fontSize = 12.sp,
                            ),
                            color = Faint,
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(bottom = 28.dp),
                        )
                    }
                }
            }
        }
        }
    }
}

@Composable
private fun RadioMarker(selected: Boolean) {
    Box(
        modifier = Modifier
            .size(20.dp)
            .clip(CircleShape)
            .border(
                width = 2.dp,
                color = if (selected) IFoxyYellow else Color.White.copy(alpha = 0.35f),
                shape = CircleShape,
            ),
        contentAlignment = Alignment.Center,
    ) {
        if (selected) {
            Box(
                modifier = Modifier
                    .size(9.dp)
                    .clip(CircleShape)
                    .background(IFoxyYellow),
            )
        }
    }
}
