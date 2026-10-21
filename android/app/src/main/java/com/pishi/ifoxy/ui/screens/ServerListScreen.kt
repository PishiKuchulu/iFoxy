package com.pishi.ifoxy.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.KeyboardArrowRight
import androidx.compose.material.icons.filled.Check
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
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
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
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
import kotlinx.coroutines.withContext

private sealed class LocationRow {
    data class RecommendedRow(val country: VpnCountry) : LocationRow()
    data class CountryHeader(val country: VpnCountry) : LocationRow()
    data class CityRow(val country: VpnCountry, val cityIndex: Int) : LocationRow()
}

private enum class PingState { PENDING, DONE, FAILED }

private val Muted = Color.White.copy(alpha = 0.55f)
private val Faint = Color.White.copy(alpha = 0.38f)

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

    val selectedState by proxyStateStore.selectedProxyFlow.collectAsState()

    val pingResults = remember { mutableStateMapOf<String, Int>() }
    val pingStates = remember { mutableStateMapOf<String, PingState>() }

    LaunchedEffect(Unit) {
        val cached = withContext(Dispatchers.IO) { serverListClient.loadCachedCountries() }
        if (cached.isNotEmpty()) {
            countries = cached
            isLoading = false
        }
        runCatching { serverListClient.fetchCountries() }
            .onSuccess { fresh ->
                countries = fresh
                errorMessage = null
            }
            .onFailure {
                if (countries.isEmpty()) {
                    errorMessage = it.message ?: "Failed to load server list"
                }
            }
        isLoading = false
    }

    val ordered = remember(countries) {
        countries.sortedWith(compareBy({ it.code != RECOMMENDED_COUNTRY_CODE }, { it.name }))
    }

    val rows = remember(ordered) {
        buildList {
            for (country in ordered) {
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

        Box(Modifier.fillMaxSize()) {
            when {
                isLoading -> CircularProgressIndicator(
                    color = IFoxyYellow,
                    modifier = Modifier.align(Alignment.Center),
                )
                errorMessage != null && countries.isEmpty() -> Text(
                    text = errorMessage.orEmpty(),
                    textAlign = TextAlign.Center,
                    color = IFoxyErrorOnDark,
                    style = TextStyle(fontFamily = PoppinsFamily, fontSize = 14.sp),
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
                                                errorMessage = "No available servers for ${row.country.name}"
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
                                    )
                                    Spacer(Modifier.weight(1f))
                                    Icon(
                                        imageVector = Icons.AutoMirrored.Filled.KeyboardArrowRight,
                                        contentDescription = null,
                                        tint = Faint,
                                        modifier = Modifier.size(18.dp),
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
                                        .clickable(role = Role.Button) {
                                            val candidates = ServerListClient.candidatesForCity(countries, row.country.code, city.code)
                                            val chosen = candidates.randomOrNull()
                                            if (chosen != null) {
                                                proxyStateStore.save(chosen)
                                                onServerSelected()
                                            } else {
                                                errorMessage = "No available servers in ${city.code}"
                                            }
                                        }
                                        .padding(start = 34.dp, top = 9.dp, bottom = 9.dp),
                                    verticalAlignment = Alignment.CenterVertically,
                                ) {
                                    RadioMarker(selected = isSelected)
                                    Spacer(Modifier.width(12.dp))
                                    Text(
                                        city.code,
                                        style = TextStyle(
                                            fontFamily = PoppinsFamily,
                                            fontWeight = if (isSelected) FontWeight.SemiBold else FontWeight.Normal,
                                            fontSize = 14.5.sp,
                                        ),
                                        color = if (isSelected) Color.White else Color.White.copy(alpha = 0.82f),
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
