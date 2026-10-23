package com.pishi.ifoxy.ui.components

import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.size
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Rect
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.drawscope.clipPath
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import kotlin.math.abs
import kotlin.math.max
import kotlin.math.sqrt

/**
 * Native port of Farzad's ripple-dots loading SVG: a 10x10 dot grid
 * inside a disc, lit by two expanding rings. The rings are masks in the
 * original — dots brighten as a ring crosses them instead of anything
 * being drawn over them. One cycle is 2.8 s; the second ring runs half
 * a cycle behind. [ink] is the dot/rim color (the SVG ships a light-ink
 * build for dark surfaces and a dark-ink build for light ones).
 */
@Composable
fun RippleDotsLoader(
    ink: Color,
    modifier: Modifier = Modifier,
    size: Dp = 72.dp,
) {
    val transition = rememberInfiniteTransition(label = "ripple-dots")
    val phase by transition.animateFloat(
        initialValue = 0f,
        targetValue = 1f,
        animationSpec = infiniteRepeatable(tween(2_800, easing = LinearEasing)),
        label = "ripple-phase",
    )

    Canvas(modifier.size(size)) {
        val unit = this.size.minDimension / 64f
        val center = Offset(this.size.width / 2f, this.size.height / 2f)
        fun point(x: Float, y: Float) = Offset(center.x + (x - 32f) * unit, center.y + (y - 32f) * unit)

        // Faint rim of the disc.
        drawCircle(
            color = ink,
            radius = 31.5f * unit,
            center = center,
            style = Stroke(width = unit),
            alpha = 0.14f,
        )

        // Ring state at cycle position u: radius grows 0 -> 38 while the
        // ring's strength fades in by 14% and out after 72% (SVG keyframes).
        fun ring(u: Float): Pair<Float, Float> {
            val opacity = when {
                u < 0.14f -> u / 0.14f
                u > 0.72f -> (1f - u) / 0.28f
                else -> 1f
            }
            return (38f * u) to opacity.coerceIn(0f, 1f)
        }
        val rings = listOf(ring(phase), ring((phase + 0.5f) % 1f))

        val disc = Path().apply {
            addOval(Rect(center.x - 32f * unit, center.y - 32f * unit, center.x + 32f * unit, center.y + 32f * unit))
        }
        clipPath(disc) {
            var gy = 3.2f
            while (gy < 64f) {
                var gx = 3.2f
                while (gx < 64f) {
                    val dx = gx - 32f
                    val dy = gy - 32f
                    val distance = sqrt(dx * dx + dy * dy)
                    var lit = 0f
                    for ((ringRadius, ringOpacity) in rings) {
                        // Ring band is 7 units wide; smooth its edges.
                        val band = (1f - abs(distance - ringRadius) / 3.5f).coerceIn(0f, 1f)
                        val soft = band * band * (3f - 2f * band)
                        lit = max(lit, soft * ringOpacity)
                    }
                    drawCircle(
                        color = ink,
                        radius = 1.15f * unit,
                        center = point(gx, gy),
                        alpha = 0.26f + 0.74f * lit,
                    )
                    gx += 6.4f
                }
                gy += 6.4f
            }
        }
    }
}
