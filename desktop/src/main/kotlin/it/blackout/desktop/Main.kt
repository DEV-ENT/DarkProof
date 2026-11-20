package it.blackout.desktop

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.painter.BitmapPainter
import androidx.compose.ui.graphics.painter.Painter
import androidx.compose.ui.graphics.toComposeImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.DpSize
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Window
import androidx.compose.ui.window.application
import androidx.compose.ui.window.rememberWindowState
import it.blackout.mesh.MainActivity
import it.blackout.mesh.MeshEngine
import it.blackout.mesh.Theme
import org.jetbrains.skia.Image

fun main(args: Array<String>) {
    if ("--self-test" in args) kotlin.system.exitProcess(SelfTest.run()) // no window: see SelfTest
    window()
}

private fun window() = application {
    val a = remember { Desktop.activity() }
    Window(onCloseRequest = { MeshEngine.shutdown(); exitApplication() }, title = "DarkProof", icon = remember { appIcon() }, state = rememberWindowState(size = DpSize(1360.dp, 860.dp))) {
        LaunchedEffect(Unit) { window.minimumSize = java.awt.Dimension(900, 620) }
        App(a)
    }
}

/** The icon in the window's corner and on the taskbar: the logo on a black tile (icons/MakeIcon.java draws it). */
internal fun appIcon(): Painter =
    BitmapPainter(Image.makeFromEncoded(object {}.javaClass.getResourceAsStream("/icon.png")!!.use { it.readBytes() }).toComposeImageBitmap())

/**
 * Everything inside the window: the desktop's layout (Shell.kt) around the phones' own screens, handed the desktop's
 * Context where they ask Android for one, and over them the short messages a phone shows at the bottom of its screen.
 * Tests draw this without a window.
 */
@Composable
internal fun App(a: MainActivity) {
    CompositionLocalProvider(LocalContext provides a) {
        Box(Modifier.fillMaxSize().background(Theme.bg)) {
            DesktopApp(a)
            Toasts.text?.let { t ->
                // Above the tab bar and the message box, and light on dark so it can't be taken for one of the screen's own cards.
                Box(Modifier.align(Alignment.BottomCenter).padding(start = 24.dp, end = 24.dp, bottom = 96.dp).clip(RoundedCornerShape(22.dp)).background(Theme.text).padding(horizontal = 18.dp, vertical = 11.dp)) {
                    Text(t, color = Color.Black, fontSize = 14.sp, lineHeight = 20.sp)
                }
            }
        }
    }
}
