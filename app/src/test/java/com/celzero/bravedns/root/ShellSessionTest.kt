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

import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Drives the shared shell against a plain `sh`. The mechanism is the same one used against
 * `su`; `sh` is simply what every unit-test host has, and it exercises the marker protocol,
 * the drain thread and the timeout path end to end.
 */
class ShellSessionTest {

    private var session: ShellSession? = null

    @After
    fun tearDown() {
        session?.close()
        session = null
    }

    private fun shell(): ShellSession {
        val (started, warmup) = ShellSession.start(arrayOf(SHELL), START_TIMEOUT_MS)
        assertNotNull("shell did not start: $warmup", started)
        return started!!.also {
            session = it
            assertTrue("warmup failed", it.alive)
        }
    }

    @Test
    fun `reports stdout and a zero exit code`() {
        val result = shell().execute("echo hello", TIMEOUT_MS)
        assertTrue(result.err, result.ok)
        assertTrue(result.out, result.out.contains("hello"))
        assertEquals("", result.err)
    }

    @Test
    fun `reports non-zero exit codes without killing the shell`() {
        val shell = shell()
        assertEquals(1, shell.execute("false", TIMEOUT_MS).code)
        assertEquals(7, shell.execute("sh -c 'exit 7'", TIMEOUT_MS).code)
        assertTrue(shell.alive)
    }

    @Test
    fun `stderr arrives with the output`() {
        val result = shell().execute("echo oops >&2", TIMEOUT_MS)
        assertTrue(result.ok)
        assertTrue(result.out, result.out.contains("oops"))
    }

    @Test
    fun `output without a trailing newline still ends the command`() {
        val result = shell().execute("printf abc", TIMEOUT_MS)
        assertTrue(result.err, result.ok)
        assertEquals("abc", result.out.trim())
    }

    @Test
    fun `output larger than a pipe buffer does not wedge the shell`() {
        val result = shell().execute("seq 1 60000", TIMEOUT_MS)
        assertTrue(result.err + result.out.takeLast(60), result.ok)
        assertTrue(result.out, result.out.contains("60000"))
    }

    @Test
    fun `the shell keeps state between commands`() {
        val shell = shell()
        shell.execute("x=42", TIMEOUT_MS)
        assertEquals("42", shell.execute("echo \$x", TIMEOUT_MS).out.trim())
    }

    @Test
    fun `a wedged command kills the shell instead of blocking the next caller`() {
        val shell = shell()
        val result = shell.execute("sleep 30", SHORT_TIMEOUT_MS)
        assertFalse(result.ok)
        assertTrue(result.err, result.err.contains("timeout"))
        assertFalse(shell.alive)
        assertEquals(-1, shell.execute("echo hi", TIMEOUT_MS).code)
    }

    @Test
    fun `a closed shell refuses further commands`() {
        val shell = shell()
        shell.close()
        assertFalse(shell.alive)
        assertEquals(-1, shell.execute("echo hi", TIMEOUT_MS).code)
    }

    @Test
    fun `start fails when the command never answers`() {
        // a shell whose stdin is not connected (some `su` implementations point it at
        // /dev/null) exits immediately: start must report that rather than hand back a
        // session that would swallow every later command
        val (started, warmup) =
            ShellSession.start(arrayOf(SHELL, "-c", "exit 0"), START_TIMEOUT_MS)
        assertNotNull(warmup.err)
        assertNull(started)
    }

    companion object {
        private const val SHELL = "sh"
        private const val START_TIMEOUT_MS = 5_000L
        private const val TIMEOUT_MS = 10_000L
        private const val SHORT_TIMEOUT_MS = 300L
    }
}
