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

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * Exercises the dispatcher against stand-in `su` binaries: shell scripts that count how
 * often they were forked. That count is the whole point of the fix — a superuser app shows
 * a grant notice per fork, so the number of `su` processes a session of commands spawns is
 * what the repeated *"…is given root level permissions"* message tracks.
 *
 * The two scripts model the two real-world cases: a `su` that hands the shell its stdin
 * (Magisk, KernelSU, SuperSU — one fork for the whole process) and one that points stdin at
 * `/dev/null` (AOSP/toybox — one fork per command, exactly as before the fix).
 */
class ProcessCommandRunnerTest {

    @get:Rule val folder = TemporaryFolder()

    private val count: File
        get() = File(folder.root, "count")

    /** A `su` that execs a shell on its own stdin, like Magisk's does. */
    private fun stdinSu(): File =
        script(
            "su",
            "echo 1 >>'$count'",
            "if [ \"\$1\" = -c ]; then",
            "  exec /bin/sh -c \"\$2\"",
            "fi",
            "shift",
            "exec \"\$@\"",
        )

    /** A `su` whose every shell reads from `/dev/null`, like the AOSP one. */
    private fun nullStdinSu(): File =
        script(
            "su",
            "echo 1 >>'$count'",
            "if [ \"\$1\" = -c ]; then",
            "  exec /bin/sh -c \"\$2\" </dev/null",
            "fi",
            "shift",
            "exec \"\$@\" </dev/null",
        )

    /** A `su` that only accepts `su <who> <command...>`, the AOSP dialect. */
    private fun whoSu(): File =
        script(
            "su",
            "echo 1 >>'$count'",
            "if [ \"\$1\" = -c ]; then exit 1; fi",
            "shift",
            "exec \"\$@\"",
        )

    private fun script(name: String, vararg body: String): File {
        val file = File(folder.root, name)
        file.writeText("#!/bin/sh\n" + body.joinToString("\n") + "\n")
        assertTrue("could not make $file executable", file.setExecutable(true))
        return file
    }

    private fun forks(): Int = if (count.exists()) count.readText().lines().count { it.isNotEmpty() } else 0

    @Test
    fun `every root command runs through one su fork`() {
        val runner = ProcessCommandRunner(stdinSu().absolutePath)

        val first = runner.run("echo one", asRoot = true)
        assertTrue(first.err, first.ok)
        assertTrue(first.out, first.out.contains("one"))
        assertEquals("one su fork should open the session", 1, forks())

        val second = runner.run("echo two", asRoot = true)
        assertTrue(second.err, second.ok)
        assertTrue(second.out, second.out.contains("two"))

        val third = runner.run("sh -c 'exit 4'", asRoot = true)
        assertEquals(4, third.code)
        assertEquals("the session must absorb every root command", 1, forks())
    }

    @Test
    fun `a non-root command never touches su`() {
        val runner = ProcessCommandRunner(stdinSu().absolutePath)
        runner.run("echo hi", asRoot = true)

        val app = runner.run("echo app-uid", asRoot = false)
        assertTrue(app.out, app.out.contains("app-uid"))
        assertEquals(1, forks())
    }

    @Test
    fun `a su without stdin falls back to one fork per command`() {
        val runner = ProcessCommandRunner(nullStdinSu().absolutePath)

        // the session attempt fails twice (both dialects), the dialect probe and the
        // command itself each fork once — but every later command must still work
        val first = runner.run("echo one", asRoot = true)
        assertTrue(first.err, first.ok)
        assertTrue(first.out, first.out.contains("one"))
        val afterFirst = forks()
        assertTrue("expected session attempts plus one fork, saw $afterFirst", afterFirst in 3..5)

        val second = runner.run("echo two", asRoot = true)
        assertTrue(second.err, second.ok)
        assertTrue(second.out, second.out.contains("two"))
        assertEquals("exactly one more su per command", 1, forks() - afterFirst)

        val third = runner.run("false", asRoot = true)
        assertEquals(1, third.code)
        assertEquals("and exactly one more again", 1, forks() - afterFirst - 1)
    }

    @Test
    fun `the who dialect gets a single session too`() {
        val runner = ProcessCommandRunner(whoSu().absolutePath)

        val first = runner.run("echo one", asRoot = true)
        assertTrue(first.err, first.ok)
        assertTrue(first.out, first.out.contains("one"))
        runner.run("echo two", asRoot = true)
        assertEquals("the rejected -c dialect costs one fork, then the session takes over", 2, forks())
    }

    @Test
    fun `a missing su reports failure instead of throwing`() {
        val runner = ProcessCommandRunner(File(folder.root, "no-such-su").absolutePath)
        val result = runner.run("echo hi", asRoot = true)
        assertEquals(-1, result.code)
        assertTrue(result.err, result.err.contains("root shell unavailable"))
        assertEquals(0, forks())
    }

    @Test
    fun `a failing su is reported as denied rather than as a crash`() {
        val runner = ProcessCommandRunner(script("su", "echo 1 >>'$count'", "exit 7").absolutePath)
        val result = runner.run("echo hi", asRoot = true)
        assertEquals(-1, result.code)
        assertTrue(result.err, result.err.contains("root shell unavailable"))
        assertTrue("both dialects are tried", forks() >= 2)
    }
}
