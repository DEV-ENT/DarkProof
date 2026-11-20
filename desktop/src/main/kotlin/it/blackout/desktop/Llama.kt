package it.blackout.desktop

import okhttp3.Call
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONArray
import org.json.JSONObject
import java.io.Closeable
import java.io.File
import java.io.IOException
import java.net.InetAddress
import java.net.Proxy
import java.net.ServerSocket
import java.security.SecureRandom
import java.util.concurrent.TimeUnit

/**
 * The AI engine: llama.cpp's own server program, started hidden beside the app with one model file, and asked over a
 * connection that never leaves this computer. It is the engine the website's dark room runs in a browser, here as the
 * program its authors publish. It is a program of its own, so a model that runs out of memory or crashes takes that
 * program down and not the app that passes messages on.
 *
 * Only this computer can reach it (it listens on 127.0.0.1), and only with a key made anew at every start, so another
 * program or a web page on this computer can't use it. Nothing it prints is kept: it could name what was asked.
 */
internal class Llama private constructor(private val process: Process, internal val port: Int, private val key: String, private val said: Tail) : Closeable {
    companion object {
        /** The engine program in this copy of the app, or null if this copy has none (a build made without it). */
        fun program(): File? {
            val resources = System.getProperty("compose.application.resources.dir") ?: return null
            return File(resources, "llama/" + if (TitleBar.onWindows) "llama-server.exe" else "llama-server").takeIf { it.isFile }
        }

        /** The command that starts the engine, without the model and the address. Tests put a stand-in program here. */
        @Volatile var command: () -> List<String>? = { program()?.let { listOf(it.path) } }

        private val http = OkHttpClient.Builder().proxy(Proxy.NO_PROXY) // never through a proxy: the engine is on this computer
            .connectTimeout(5, TimeUnit.SECONDS).readTimeout(QUIET_S, TimeUnit.SECONDS).build()
        private const val QUIET_S = 120L   // an answer that says nothing for this long is given up
        private const val LOAD_S = 240L    // a large model read from a slow disk takes its time
        private val JSON = "application/json".toMediaType()

        /**
         * How many tokens a model may spend thinking before it answers: none. Left to themselves these models think
         * for a thousand tokens and more before the first word. Tried on real models (2026-11-20, Qwen 3.5 2B and 4B):
         * the 2B used its whole answer up on thinking and said nothing; the 4B with 768 tokens of thinking answered
         * better, but only after as long as it takes to write those 768 tokens, which on a computer's processor alone
         * is a minute or so of nothing on the screen. Tests on real models can set another value to compare.
         */
        @Volatile var THINKING = 0

        /**
         * Starts the engine with [model] and waits until the model is loaded. [context] is the most tokens it holds
         * at once: instructions, the conversation, and the answer. Throws with the engine's own last lines if it
         * doesn't come up.
         */
        fun start(model: File, context: Int): Llama {
            val base = command() ?: throw IOException("This copy of DarkProof has no AI engine.")
            val port = ServerSocket(0, 1, InetAddress.getLoopbackAddress()).use { it.localPort }
            val key = ByteArray(24).also(SecureRandom()::nextBytes).joinToString("") { "%02x".format(it) }
            // --offline: the engine itself never goes to the network. --no-webui, --no-slots: no pages and no view of what is asked.
            val builder = ProcessBuilder(base + listOf("-m", model.path, "--host", "127.0.0.1", "--port", "$port", "--api-key", key, "-c", "$context",
                "--offline", "--no-webui", "--no-slots", "--reasoning-budget", "$THINKING"))
            builder.environment().keys.removeIf { it.startsWith("LLAMA_") } // its settings come from here, not from what happens to be set on this computer
            File(base.first()).parentFile?.takeIf { it.isDirectory }?.let(builder::directory) // its libraries lie next to it
            builder.redirectErrorStream(true)
            val process = builder.start()
            val said = Tail(process)
            val llama = Llama(process, port, key, said)
            try {
                val end = System.nanoTime() + LOAD_S * 1_000_000_000L
                while (true) {
                    if (!process.isAlive) throw IOException("The AI engine stopped while loading the model. " + said.last())
                    if (llama.loaded()) return llama
                    if (System.nanoTime() > end) throw IOException("The model took too long to load.")
                    Thread.sleep(200)
                }
            } catch (t: Throwable) { llama.close(); throw t }
        }

        /** What a model said, without what it thought out loud first: models mark that part, and it is not for the reader. */
        fun shown(text: String): String {
            var t = text
            for ((open, close) in listOf("<think>" to "</think>", "<|channel>thought" to "<channel|>")) {
                while (true) {
                    val a = t.indexOf(open); if (a < 0) break
                    val b = t.indexOf(close, a + open.length)
                    t = if (b < 0) t.substring(0, a) else t.substring(0, a) + t.substring(b + close.length) // not closed yet: still thinking
                }
            }
            return t.trim()
        }

        /** The engine's version line, to check that this copy's engine runs on this computer at all; null if it doesn't. */
        fun version(): String? = runCatching {
            val base = command() ?: return null
            val p = ProcessBuilder(base + "--version").redirectErrorStream(true).also { b -> File(base.first()).parentFile?.takeIf { it.isDirectory }?.let(b::directory) }.start()
            val out = p.inputStream.bufferedReader().readText()
            if (!p.waitFor(30, TimeUnit.SECONDS)) { p.destroyForcibly(); return null }
            out.lines().firstOrNull { it.contains("version", ignoreCase = true) }?.trim()?.take(200).takeIf { p.exitValue() == 0 }
        }.getOrNull()
    }

    /** The last lines the engine printed, kept in memory only, for the message when it fails to start. */
    private class Tail(process: Process) {
        private val lines = ArrayDeque<String>()
        init {
            Thread({
                runCatching { process.inputStream.bufferedReader().forEachLine { l -> synchronized(lines) { lines.addLast(l); if (lines.size > 30) lines.removeFirst() } } }
            }, "ai-engine-output").apply { isDaemon = true }.start()
        }
        fun last(): String = synchronized(lines) { lines.filter { it.contains("error", ignoreCase = true) || it.contains("fail", ignoreCase = true) }.takeLast(2).ifEmpty { lines.takeLast(1) } }
            .joinToString(" ") { it.trim().take(200) }
    }

    @Volatile private var call: Call? = null
    val alive get() = process.isAlive
    val pid get() = process.pid()

    private fun request(path: String) = Request.Builder().url("http://127.0.0.1:$port$path").header("Authorization", "Bearer $key")

    private fun loaded(): Boolean = runCatching { http.newCall(request("/health").build()).execute().use { it.code == 200 } }.getOrDefault(false)

    /**
     * Asks [question] after [history] (pairs of who, "user" or "assistant", and what they said) under the [system]
     * instructions. [onText] gets the answer so far as it grows. Returns the whole answer; throws if the engine fails.
     * [stop] ends it from another thread, and what was said until then is returned.
     */
    fun chat(system: String, history: List<Pair<String, String>>, question: String, maxTokens: Int, onText: (String) -> Unit): String {
        val messages = JSONArray().put(JSONObject().put("role", "system").put("content", system))
        for ((who, text) in history) messages.put(JSONObject().put("role", who).put("content", text))
        messages.put(JSONObject().put("role", "user").put("content", question))
        val body = JSONObject().put("messages", messages).put("stream", true).put("max_tokens", maxTokens)
            .put("temperature", 0.7).put("top_k", 40).put("top_p", 0.95)
        val c = http.newCall(request("/v1/chat/completions").post(body.toString().toRequestBody(JSON)).build())
        call = c
        val text = StringBuilder(); var cut = false
        try {
            c.execute().use { r ->
                if (r.code != 200) throw IOException("The AI engine answered ${r.code}. " + r.body?.string().orEmpty().take(200))
                val source = r.body!!.source()
                while (true) {
                    val line = source.readUtf8Line() ?: break
                    if (!line.startsWith("data:")) continue
                    val data = line.substring(5).trim()
                    if (data == "[DONE]") break
                    val choice = runCatching { JSONObject(data).optJSONArray("choices")?.optJSONObject(0) }.getOrNull() ?: continue
                    if (choice.optString("finish_reason") == "length") cut = true // it ran out of room before it was done
                    val delta = choice.optJSONObject("delta") ?: continue
                    val piece = if (delta.isNull("content")) "" else delta.optString("content")
                    if (piece.isNotEmpty()) { text.append(piece); onText(shown(text.toString())) }
                }
            }
        } catch (e: IOException) {
            if (!c.isCanceled()) throw IOException(if (process.isAlive) e.message ?: "The connection to the AI engine broke." else "The AI engine stopped. " + said.last())
        } finally { call = null }
        return shown(text.toString()).let { if (cut && it.isNotEmpty()) "$it\n\n(The answer was cut off here: it got too long.)" else it }
    }

    /** Ends the answer being given, if any. */
    fun stop() { call?.cancel() }

    override fun close() {
        call?.cancel()
        process.destroy()
        if (!process.waitFor(3, TimeUnit.SECONDS)) process.destroyForcibly()
    }
}
