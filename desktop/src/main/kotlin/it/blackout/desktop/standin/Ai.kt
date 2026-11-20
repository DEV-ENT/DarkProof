package it.blackout.mesh

import android.content.Context
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue

// The phones' on-device AI (app/.../LocalAi.kt), as the screens see it. There is no AI engine in the desktop app yet.
// So that the Ask screen says so itself instead of offering phone downloads, it is given one stand-in "model" that
// is always ready and answers every question with that one honest line.

data class AiModel(
    val id: String, val title: String, val detail: String, val license: String, val url: String,
    val bytes: Long, val sha256: String, val minMemoryGB: Int = 0,
)

object LocalAi {
    private const val NOT_YET = "The AI isn't on the desktop yet. It runs in the phone apps, with no internet."
    val all = listOf(AiModel("desktop", "Not on the desktop yet", "", "", "", 0, ""))
    const val instructions = ""
    const val situationIntro = ""

    sealed class State {
        object Missing : State()
        data class Downloading(val progress: Float, val waiting: String? = null) : State()
        object Verifying : State()
        object Ready : State()
        data class Failed(val why: String) : State()
    }
    data class Turn(val role: String, val text: String, val isError: Boolean = false)

    val states = mutableStateMapOf<String, State>("desktop" to State.Ready)
    var selected by mutableStateOf<String?>("desktop"); private set
    val conversation = mutableStateListOf(Turn("assistant", NOT_YET))
    var busy by mutableStateOf(false); private set
    var memoryGB = (Runtime.getRuntime().maxMemory() shr 30).toInt().coerceAtLeast(4); private set
    val catalog get() = all

    fun model(id: String?) = all.firstOrNull { it.id == id }
    fun select(m: AiModel) {}
    fun network(c: Context): String = ""
    fun spaceProblem(m: AiModel): String? = null
    fun download(m: AiModel, mobileData: Boolean = true) {}
    fun cancel(m: AiModel) {}
    fun delete(m: AiModel) {}
    fun typicalSeconds(m: AiModel): Int? = null
    fun newConversation() { conversation.clear(); conversation += Turn("assistant", NOT_YET) }
    fun stop() {}
    fun ask(question: String, system: String, done: ((Turn) -> Unit)? = null) {
        conversation += Turn("user", question)
        val answer = Turn("assistant", NOT_YET)
        conversation += answer; done?.invoke(answer)
    }
}
