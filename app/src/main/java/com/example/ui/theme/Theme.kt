package com.example.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

private val DarkColorScheme = darkColorScheme(
    primary = CyanPrimaryDark,
    onPrimary = Color(0xFF17210D),
    primaryContainer = Color(0xFF2D4320),
    onPrimaryContainer = Color(0xFFD9F8B7),
    secondary = BlueSecondaryDark,
    onSecondary = Color(0xFF09231D),
    secondaryContainer = Color(0xFF21463D),
    onSecondaryContainer = Color(0xFFC5F2E5),
    tertiary = EmeraldTertiaryDark,
    onTertiary = Color(0xFF102719),
    background = DarkBackground,
    onBackground = Color(0xFFF1F6F1),
    surface = DarkSurface,
    onSurface = Color(0xFFF1F6F1),
    surfaceVariant = DarkSurfaceVariant,
    onSurfaceVariant = Color(0xFFB5C2BE),
    outline = DarkBorder,
    outlineVariant = Color(0xFF35464A),
    error = DisconnectedRed,
    onError = Color(0xFF3A0808)
)

private val LightColorScheme = lightColorScheme(
    primary = CyanPrimaryLight,
    onPrimary = Color.White,
    primaryContainer = Color(0xFFDDF2C7),
    onPrimaryContainer = Color(0xFF1B2A0D),
    secondary = BlueSecondaryLight,
    onSecondary = Color.White,
    secondaryContainer = Color(0xFFD2F1E8),
    onSecondaryContainer = Color(0xFF092A22),
    tertiary = EmeraldTertiaryLight,
    onTertiary = Color.White,
    background = LightBackground,
    onBackground = Color(0xFF18211C),
    surface = LightSurface,
    onSurface = Color(0xFF18211C),
    surfaceVariant = LightSurfaceVariant,
    onSurfaceVariant = Color(0xFF526159),
    outline = LightBorder,
    outlineVariant = Color(0xFFD0DAD0),
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
