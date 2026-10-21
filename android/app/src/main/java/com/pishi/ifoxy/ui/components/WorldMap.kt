package com.pishi.ifoxy.ui.components

import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.drawscope.withTransform

/** Map layer width in the generated coordinate space. */
private const val MAP_W = 760f

/** Map layer height in the generated coordinate space (2:1). */
private const val MAP_H = 380f

/**
 * Filled world map from [WorldMapRings], drawn in the design's style: a
 * 200%-wide layer that drifts left and wraps seamlessly (Motion & Glow
 * spec: translateX 0 -> -50%, linear, infinite; 90 s while connected,
 * 120 s while disconnected). With [driftMillis] = null the map is static
 * (sign-in / splash backgrounds).
 *
 * The composable sizes itself to its modifier; the map band keeps its 2:1
 * aspect based on the layer width (half the canvas width).
 */
@Composable
fun WorldMapLayer(
    color: Color,
    driftMillis: Int?,
    modifier: Modifier = Modifier,
) {
    val mapPath = remember {
        Path().apply {
            for (ring in WorldMapRings) {
                if (ring.size < 4) continue
                moveTo(ring[0], ring[1])
                var i = 2
                while (i + 1 < ring.size) {
                    lineTo(ring[i], ring[i + 1])
                    i += 2
                }
                close()
            }
        }
    }

    val driftFraction: Float = if (driftMillis != null) {
        val transition = rememberInfiniteTransition(label = "world-map-drift")
        val animated by transition.animateFloat(
            initialValue = 0f,
            targetValue = 1f,
            animationSpec = infiniteRepeatable(
                animation = tween(durationMillis = driftMillis, easing = LinearEasing),
                repeatMode = RepeatMode.Restart,
            ),
            label = "world-map-drift-fraction",
        )
        animated
    } else {
        0f
    }

    Canvas(modifier = modifier) {
        // One map copy is exactly half the canvas width (the layer is 200%
        // wide); drawing two copies and shifting by up to one copy width
        // gives the seamless -50% loop from the motion spec.
        val copyWidth = size.width / 2f
        val scale = copyWidth / MAP_W
        val mapHeight = MAP_H * scale
        val top = (size.height - mapHeight) / 2f
        val shift = -driftFraction * copyWidth
        for (copy in 0..1) {
            withTransform({
                translate(left = shift + copy * copyWidth, top = top)
                scale(scaleX = scale, scaleY = scale, pivot = androidx.compose.ui.geometry.Offset.Zero)
            }) {
                drawPath(mapPath, color = color)
            }
        }
    }
}
