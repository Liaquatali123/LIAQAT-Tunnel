package com.example.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

private val DarkColorScheme = darkColorScheme(
    primary = CyanPrimaryDark,
    onPrimary = Color(0xFF101735),
    primaryContainer = Color(0xFF29345F),
    onPrimaryContainer = Color(0xFFE0E5FF),
    secondary = BlueSecondaryDark,
    onSecondary = Color(0xFF08232B),
    secondaryContainer = Color(0xFF174451),
    onSecondaryContainer = Color(0xFFC9F7FF),
    tertiary = EmeraldTertiaryDark,
    onTertiary = Color(0xFF24183D),
    background = DarkBackground,
    onBackground = Color(0xFFF1F6F1),
    surface = DarkSurface,
    onSurface = Color(0xFFF1F6F1),
    surfaceVariant = DarkSurfaceVariant,
    onSurfaceVariant = Color(0xFFB3C0D8),
    outline = DarkBorder,
    outlineVariant = Color(0xFF354563),
    error = DisconnectedRed,
    onError = Color(0xFF3A0808)
)

private val LightColorScheme = lightColorScheme(
    primary = CyanPrimaryLight,
    onPrimary = Color.White,
    primaryContainer = Color(0xFFE2E7FF),
    onPrimaryContainer = Color(0xFF18265D),
    secondary = BlueSecondaryLight,
    onSecondary = Color.White,
    secondaryContainer = Color(0xFFD9F5F9),
    onSecondaryContainer = Color(0xFF07323C),
    tertiary = EmeraldTertiaryLight,
    onTertiary = Color.White,
    background = LightBackground,
    onBackground = Color(0xFF18211C),
    surface = LightSurface,
    onSurface = Color(0xFF18211C),
    surfaceVariant = LightSurfaceVariant,
    onSurfaceVariant = Color(0xFF56627A),
    outline = LightBorder,
    outlineVariant = Color(0xFFD6DEEC),
    error = DisconnectedRed,
    onError = Color.White
)

@Composable
fun CustomTunnelProTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit
) {
    val colorScheme = if (darkTheme) DarkColorScheme else LightColorScheme

    MaterialTheme(
        colorScheme = colorScheme,
        typography = Typography,
        content = content
    )
}
