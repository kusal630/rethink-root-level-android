/*
 * Copyright 2026 RethinkDNS and its authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.celzero.bravedns.root

import android.os.Build
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit

/**
 * Outcome of a single shell invocation. Never thrown, never null: a command that could
 * not be started at all is reported as [code] `-1` with the reason in [err], so callers
 * can treat "no root binary", "su denied" and "command failed" uniformly.
 */
data class ShellResult(val code: Int, val out: String, val err: String) {
    val ok: Boolean
        get() = code == 0

    companion object {
        fun notRun(reason: String) = ShellResult(-1, "", reason)
    }
}

/**
 * Abstraction over "run a shell command". The root stack only ever talks to this, so the
 * whole root path can be exercised in unit tests with a recording fake and without ever
 * touching a real `su`.
 */
interface CommandRunner {
    /**
     * Runs [command]. When [asRoot] is true the command must execute with uid 0.
     * Implementations must not throw.
     */
    fun run(command: String, asRoot: Boolean, timeoutMs: Long = DEFAULT_TIMEOUT_MS): ShellResult

    companion object {
        const val DEFAULT_TIMEOUT_MS = 15_000L

        /** Joins independent commands into one shell line; the last exit code wins. */
        fun script(commands: List<String>): String = commands.joinToString(" ; ")
    }
}

/**
 * Runs commands through `su` (root) or `sh -c` (app uid).
 *
 * Two `su` dialects are supported, because they really do differ in the wild:
 *
 *  * **flag** — Magisk, KernelSU, SuperSU: `su -c '<command>'`
 *  * **who**  — AOSP/toybox `su` (userdebug builds, emulators, some ROMs):
 *    `su <who> <command...>`, whose `su -c` fails with `invalid uid/gid`
 *
 * The dialect is probed once per process with a harmless `echo` and only a hit is cached,
 * so a superuser grant that arrives later still gets used. An app with no usable `su`
 * reports a failure rather than throwing, and the caller falls back to the non-root path.
 *
 * **One root shell instead of one `su` fork per command.** Root commands used to fork their
 * own `su`, so a counters poll (every 90 s), a firewall sync and a tun re-establish each
 * re-issued a superuser request — on a rooted device that is what the superuser app shows
 * as the repeated *"…is given root level permissions"* notice. When the device's `su` hands
 * a shell its stdin (Magisk, KernelSU, SuperSU), [ShellSession] is opened once and every
 * root command is written to it; `su` is then forked only when the session starts.
 *
 * Not every `su` does hand over stdin — the AOSP-style `su` used by some emulators and
 * ROMs runs each command with stdin on `/dev/null`. Those devices drop to one fork per
 * command exactly as before, after a single failed session attempt, so the shared shell is
 * an optimisation and never a regression.
 */
class ProcessCommandRunner(private val suBinary: String = SU_BINARY) : CommandRunner {

    /** Root commands are serialised: one shell, one writer. */
    private val rootLock = Any()

    @Volatile private var session: ShellSession? = null

    /** Set when this device's `su` cannot be driven over stdin. */
    @Volatile private var sessionUnsupported = false

    /** Whether a session has ever opened here; separates "unsupported" from "transient". */
    @Volatile private var sessionEverOpened = false

    /** Consecutive failed opens after a session has worked before. */
    private var reopenFailures = 0

    override fun run(command: String, asRoot: Boolean, timeoutMs: Long): ShellResult {
        if (!asRoot) return exec(arrayOf(SHELL, "-c", command), command, timeoutMs)
        synchronized(rootLock) {
            val shell = session(timeoutMs) ?: return perCommand(command, timeoutMs)
            val result = shell.execute(command, timeoutMs)
            if (shell.alive) return result
            // the shell died under us (idle timeout, revoked grant, killed by the
            // superuser app): reopen and run the command once more before giving up
            dropSession()
            val fresh = session(timeoutMs) ?: return perCommand(command, timeoutMs)
            val retried = fresh.execute(command, timeoutMs)
            if (!fresh.alive) dropSession()
            return retried
        }
    }

    /**
     * The shared root shell, opened on first use. Returns null when this device cannot be
     * driven over stdin, which routes the caller to [perCommand].
     */
    private fun session(timeoutMs: Long): ShellSession? {
        session?.takeIf { it.alive }?.let { return it }
        dropSession()
        if (sessionUnsupported) return null

        val opened = openSession(timeoutMs)
        if (opened != null) {
            session = opened
            sessionEverOpened = true
            reopenFailures = 0
            return opened
        }
        // never worked here: this `su` does not forward stdin, stop trying
        if (!sessionEverOpened || ++reopenFailures >= REOPEN_FAILURE_LIMIT) {
            sessionUnsupported = true
        }
        return null
    }

    private fun dropSession() {
        session?.close()
        session = null
    }

    /**
     * The classic one-fork-per-command path: probe the dialect (cached on a hit) and run
     * the command as `su -c '<command>'` / `su <who> sh -c '<command>'`.
     */
    private fun perCommand(command: String, timeoutMs: Long): ShellResult {
        return when (detectSuStyle(timeoutMs)) {
            SuStyle.FLAG_C -> exec(arrayOf(suBinary, "-c", command), command, timeoutMs)
            SuStyle.WHO_COMMAND ->
                exec(arrayOf(suBinary, ROOT_WHO, SHELL, "-c", command), command, timeoutMs)
            SuStyle.UNKNOWN -> ShellResult.notRun("root shell unavailable ($probeDetail)")
        }
    }

    /**
     * Finds the `su` invocation this device accepts. Caches a hit for the life of the
     * process; deliberately does not cache a miss, because a superuser app may grant
     * permission later without the app restarting.
     */
    private fun detectSuStyle(timeoutMs: Long): SuStyle {
        suStyle.takeIf { it != SuStyle.UNKNOWN }?.let { return it }
        val flagC = exec(arrayOf(suBinary, "-c", "echo $STYLE_PROBE"), STYLE_PROBE, timeoutMs)
        if (flagC.out.contains(STYLE_PROBE)) {
            return SuStyle.FLAG_C.also { suStyle = it }
        }
        val who =
            exec(arrayOf(suBinary, ROOT_WHO, SHELL, "-c", "echo $STYLE_PROBE"), STYLE_PROBE, timeoutMs)
        if (who.out.contains(STYLE_PROBE)) {
            return SuStyle.WHO_COMMAND.also { suStyle = it }
        }
        probeDetail = "[-c ${describe(flagC)}] [who ${describe(who)}]"
        return SuStyle.UNKNOWN
    }

    /**
     * Opens a root shell, preferring the dialect that worked last and falling back to the
     * other one. A dialect only counts once its shell answers a no-op with exit code 0, so
     * a failed attempt is never remembered as a success.
     */
    private fun openSession(timeoutMs: Long): ShellSession? {
        for (style in stylesToTry()) {
            val (shell, warmup) = ShellSession.start(argvForSession(style), timeoutMs)
            if (shell != null) {
                suStyle = style
                probeDetail = ""
                return shell
            }
            probeDetail = "$style ${describe(warmup)}"
        }
        return null
    }

    /** How to start an interactive root shell in [style]. */
    private fun argvForSession(style: SuStyle): Array<String> =
        when (style) {
            SuStyle.FLAG_C -> arrayOf(suBinary, "-c", "exec $SHELL")
            else -> arrayOf(suBinary, ROOT_WHO, SHELL, "-c", "exec $SHELL")
        }

    /** The dialect that worked last first, then the other one. */
    private fun stylesToTry(): List<SuStyle> {
        val order = listOf(SuStyle.FLAG_C, SuStyle.WHO_COMMAND)
        val cached = suStyle
        return if (order.contains(cached)) listOf(cached) + order.filter { it != cached } else order
    }

    private fun describe(r: ShellResult): String =
        "rc=${r.code} out=${r.out.trim().take(80).replace('\n', ' ')} " +
            "err=${r.err.trim().take(80).replace('\n', ' ')}"

    /** How this device's `su` wants to be told what to run. */
    private enum class SuStyle {
        UNKNOWN,

        /** `su -c '<command>'` — Magisk, KernelSU, SuperSU. */
        FLAG_C,

        /** `su <who> <command...>` — AOSP/toybox `su`. */
        WHO_COMMAND,
    }

    @Volatile private var suStyle: SuStyle = SuStyle.UNKNOWN

    /** What the last failed probe or shell-open attempt actually saw. */
    @Volatile private var probeDetail: String = ""

    private fun exec(argv: Array<String>, display: String, timeoutMs: Long): ShellResult {
        return try {
            val process = ProcessBuilder(*argv).redirectErrorStream(false).start()
            val out = Drain(process.inputStream)
            val err = Drain(process.errorStream)
            if (!waitFor(process, timeoutMs)) {
                destroyForcibly(process)
                ShellResult.notRun("timeout after ${timeoutMs}ms: $display")
            } else {
                ShellResult(process.exitValue(), out.await(), err.await())
            }
        } catch (e: IOException) {
            ShellResult.notRun("${e.javaClass.simpleName}: ${e.message}")
        } catch (e: InterruptedException) {
            Thread.currentThread().interrupt()
            ShellResult.notRun("interrupted")
        }
    }

    /**
     * Waits up to [timeoutMs] for [process] to exit.
     *
     * Polls `exitValue()` on a monotonic clock rather than `Process.waitFor(long,
     * TimeUnit)` (API 26) or `SystemClock.uptimeMillis()` (an Android-only stub a JVM unit
     * test cannot call), so the same code path runs on every supported device and in tests.
     * The timeout is a bound on how long the caller blocks either way — the process
     * outlives it and is killed by [destroyForcibly].
     */
    private fun waitFor(process: Process, timeoutMs: Long): Boolean {
        val deadline = System.nanoTime() + timeoutMs * 1_000_000
        while (true) {
            try {
                process.exitValue()
                return true
            } catch (e: IllegalThreadStateException) {
                if (System.nanoTime() >= deadline) return false
                try {
                    Thread.sleep(POLL_INTERVAL_MS)
                } catch (ie: InterruptedException) {
                    Thread.currentThread().interrupt()
                    return false
                }
            }
        }
    }

    /** `Process.destroyForcibly()` is API 26 as well; `destroy()` exists everywhere. */
    private fun destroyForcibly(process: Process) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            process.destroyForcibly()
        } else {
            process.destroy()
        }
    }

    /**
     * Reads [stream] on a background thread while the child is still running: a shell that
     * writes more than a pipe buffer (`iptables -L -vnx` over a large rule set) would
     * otherwise fill the pipe, block, and never reach exit — leaving [waitFor] to time out
     * on a process waiting to be read from.
     *
     * [await] joins that reader first, so the returned text is the child's complete output.
     * Snapshotting the buffer straight after [Thread.start] would race the reader and hand
     * back an empty string for a child that exited promptly.
     */
    private class Drain(stream: InputStream) {
        private val bytes = ByteArrayOutputStream()
        private val thread: Thread

        init {
            thread =
                Thread(
                    {
                        val buf = ByteArray(4096)
                        try {
                            while (true) {
                                val n = stream.read(buf)
                                if (n < 0) break
                                synchronized(bytes) { bytes.write(buf, 0, n) }
                            }
                        } catch (_: IOException) {
                            // process went away; whatever was read is still useful
                        } finally {
                            try {
                                stream.close()
                            } catch (_: IOException) {
                            }
                        }
                    },
                    "root-shell-drain",
                )
            thread.isDaemon = true
            thread.start()
        }

        fun await(): String {
            try {
                thread.join(DRAIN_JOIN_MS)
            } catch (e: InterruptedException) {
                Thread.currentThread().interrupt()
            }
            synchronized(bytes) {
                return String(bytes.toByteArray(), Charsets.UTF_8)
            }
        }

        companion object {
            /** Generous: the child has already exited by the time we get here. */
            private const val DRAIN_JOIN_MS = 5_000L
        }
    }

    companion object {
        private const val SU_BINARY = "su"
        private const val SHELL = "sh"

        /** Who to become for the WHO_COMMAND dialect: `0`/`root` are both accepted. */
        private const val ROOT_WHO = "0"

        /** Echoed by both probe forms so a match cannot come from su's own chatter. */
        private const val STYLE_PROBE = "rethink-su-style-ok"

        /**
         * A session that worked once and then failed to reopen twice is treated as
         * unsupported: reopening on every command would fork more `su` than it saves.
         */
        private const val REOPEN_FAILURE_LIMIT = 2

        private const val POLL_INTERVAL_MS = 25L
    }
}

/**
 * A single long-lived root shell, opened once and reused for every root command.
 *
 * Each [execute] writes the command and an `echo '<sentinel>:<code>'` marker to the shell's
 * stdin, then reads stdout until that marker. `redirectErrorStream` merges stderr into
 * stdout in the child, so output comes back interleaved and in order, and a daemon thread
 * drains the stream into a queue the whole time — a command that writes more than a pipe
 * buffer (e.g. `iptables -L -vnx` over a large rule set) can neither fill the pipe nor
 * deadlock the shell.
 *
 * The shell is only usable when its `su` hands stdin through; [start] proves that with a
 * no-op and reports failure instead of handing back a shell that would silently swallow
 * every command.
 */
internal class ShellSession(private val process: Process) {

    @Volatile var alive = true
        private set

    private val input = process.outputStream
    private val lines = LinkedBlockingQueue<Any>()

    /** Distinct from every line of output, so a marker can never be queued by mistake. */
    private val eof = Any()

    /** Unique per session, so command output cannot be mistaken for a marker. */
    private val sentinel = "__rzn${Integer.toHexString(System.identityHashCode(this))}_"

    private var sequence = 0

    init {
        Thread({ drain() }, "root-shell-reader").apply {
            isDaemon = true
            start()
        }
    }

    fun execute(command: String, timeoutMs: Long): ShellResult {
        if (!alive) return ShellResult.notRun("root shell is not running")
        val marker = "$sentinel${sequence++}"
        return try {
            input.write("$command\necho \"$marker:\$?\"\n".toByteArray(Charsets.UTF_8))
            input.flush()
            collect(command, marker, timeoutMs)
        } catch (e: IOException) {
            close()
            ShellResult.notRun("root shell write failed: ${e.message}")
        }
    }

    private fun collect(command: String, marker: String, timeoutMs: Long): ShellResult {
        val out = StringBuilder()
        val deadline = System.nanoTime() + timeoutMs * 1_000_000
        while (true) {
            val remainingNs = deadline - System.nanoTime()
            if (remainingNs <= 0L) return timedOut(command, timeoutMs)
            val line =
                lines.poll(remainingNs / 1_000_000 + 1, TimeUnit.MILLISECONDS)
                    ?: return timedOut(command, timeoutMs)
            if (line === eof) {
                close()
                return ShellResult.notRun("root shell exited: $command")
            }
            val text = line as? String ?: continue
            // `indexOf`, not `startsWith`: a command that printed its last line without
            // a trailing newline would otherwise glue itself to the marker
            val at = text.indexOf(marker)
            if (at < 0) {
                out.append(text).append('\n')
                continue
            }
            if (at > 0) out.append(text, 0, at).append('\n')
            val rest = text.substring(at + marker.length).removePrefix(":").trim()
            return ShellResult(rest.toIntOrNull() ?: -1, out.toString(), "")
        }
    }

    /**
     * A wedged command must not hold the root lock forever: kill the shell and let the
     * next call open a fresh one rather than blocking every other root caller.
     */
    private fun timedOut(command: String, timeoutMs: Long): ShellResult {
        close()
        return ShellResult.notRun("timeout after ${timeoutMs}ms: $command")
    }

    fun close() {
        alive = false
        try {
            input.close()
        } catch (_: IOException) {
        }
        try {
            // `destroyForcibly()` is API 26, minSdk here is 23; Throwable also covers the
            // stubbed android.jar a unit test runs against, where SDK_INT is not readable
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) process.destroyForcibly()
            else process.destroy()
        } catch (_: Throwable) {
        }
    }

    private fun drain() {
        try {
            process.inputStream.bufferedReader(Charsets.UTF_8).use { reader ->
                while (true) {
                    lines.put(reader.readLine() ?: break)
                }
            }
        } catch (_: IOException) {
            // shell went away; whatever was read is still useful
        } finally {
            lines.put(eof)
        }
    }

    companion object {
        /** No-op that proves the shell is really ours: exit code must be 0. */
        private const val NOOP = ":"

        /**
         * Starts a shell from [argv] and proves it works with [NOOP]. Returns the shell only
         * when that no-op exited 0, alongside whatever the attempt printed — a shell whose
         * stdin is not connected (some `su` implementations point it at `/dev/null`) fails
         * here instead of swallowing every later command.
         */
        fun start(argv: Array<String>, timeoutMs: Long): Pair<ShellSession?, ShellResult> {
            val process =
                try {
                    ProcessBuilder(*argv).redirectErrorStream(true).start()
                } catch (e: IOException) {
                    return null to ShellResult.notRun("${e.javaClass.simpleName}: ${e.message}")
                }
            val session = ShellSession(process)
            val warmup = session.execute(NOOP, timeoutMs)
            if (!session.alive || !warmup.ok) {
                session.close()
                return null to warmup
            }
            return session to warmup
        }
    }
}

/** State of root availability on this device. */
enum class RootState {
    /** Not probed yet. */
    UNKNOWN,

    /** `su` exists and granted uid 0. */
    GRANTED,

    /** `su` exists but the grant was refused / not elevated. */
    DENIED,

    /** No `su` binary on PATH at all. */
    UNAVAILABLE,
}

/**
 * Probes (and caches) root availability.
 *
 * Denials are cached for longer than grants: re-forking `su` on every sync is both a
 * battery cost and a UX annoyance when the user pressed "deny" in the superuser app.
 */
class RootDetector(
    private val runner: CommandRunner,
    private val clock: () -> Long = System::currentTimeMillis,
    private val grantTtlMs: Long = GRANT_TTL_MS,
    private val denyTtlMs: Long = DENY_TTL_MS,
    private val log: (String) -> Unit = {},
) {
    @Volatile private var state: RootState = RootState.UNKNOWN
    @Volatile private var probedAt: Long = 0L

    fun state(): RootState = state

    /**
     * Returns true when a root shell is usable. Cached for [grantTtlMs] after a success
     * and [denyTtlMs] after a failure, unless [force] is set.
     */
    fun isGranted(force: Boolean = false): Boolean {
        val now = clock()
        val ttl = if (state == RootState.GRANTED) grantTtlMs else denyTtlMs
        if (!force && state != RootState.UNKNOWN && now - probedAt < ttl) {
            return state == RootState.GRANTED
        }
        val result = probe()
        state = result
        probedAt = now
        return result == RootState.GRANTED
    }

    private fun probe(): RootState {
        val hasSu =
            runner.run("command -v su >/dev/null 2>&1", asRoot = false, timeoutMs = PROBE_TIMEOUT_MS)
        if (!hasSu.ok) {
            log("root probe: no su on PATH")
            return RootState.UNAVAILABLE
        }

        val who = runner.run("id", asRoot = true, timeoutMs = PROBE_TIMEOUT_MS)
        if (who.ok && who.out.contains(ROOT_UID_MARKER)) {
            log("root probe: granted")
            return RootState.GRANTED
        }
        // one line, because "denied" and "su dialect refused us" look identical otherwise
        log(
            "root probe: denied (code=${who.code}, out=${who.out.trim().take(120)}, " +
                "err=${who.err.trim().take(120)})",
        )
        return RootState.DENIED
    }

    companion object {
        const val ROOT_UID_MARKER = "uid=0"
        const val PROBE_TIMEOUT_MS = 10_000L
        const val GRANT_TTL_MS = 5 * 60_000L
        const val DENY_TTL_MS = 30 * 60_000L
    }
}
