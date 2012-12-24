/**
 * @author Tadanori TERUYA &lt;tadanori.teruya@gmail.com&gt; (2012)
 * @license: The MIT license &lt;http://opensource.org/licenses/MIT&gt;
 */
/*
 * Copyright (c) 2012 Tadanori TERUYA (tell) <tadanori.teruya@gmail.com>
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation files
 * (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge,
 * publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * @license: The MIT license <http://opensource.org/licenses/MIT>
 */
package com.github.emboss.siphash;

import org.junit.Before;
import org.junit.Test;

import java.security.MessageDigest;

import static org.junit.Assert.assertEquals;

/**
 * Several test cases are based on a class {@code SipHashTest}.
 *
 * @author Tadanori TERUYA &lt;tadanori.teruya@gmail.com&gt; (2012)
 */
public class SipHashMDTest {

    protected SipKey sipKey = SipHashTest.SPEC_KEY;
    private MessageDigest sipHashMD;

    @Before
    public void setupKeyAndMD() {
        sipHashMD = new SipHashMD(null);
        ((SipHashMD) sipHashMD).setSipKey(sipKey);
    }

    @Test
    public void checkAlgorithmName() {
        final String name = "SipHash-2-4";
        assertEquals(sipKey.getAlgorithm(), name);
        assertEquals(sipHashMD.getAlgorithm(), name);
    }

    @Test
    public void spec() {
        final byte[] msg = com.github.emboss.siphash.SipHashTest.SPEC_MSG;
        sipHashMD.update(msg);
        final long digest = ((SipHashMD) sipHashMD).digestLong();
        assertEquals(0xa129ca6149be45e5L, digest);
    }

    @Test
    public void emptyString() throws Exception {
        final byte[] msg = "".getBytes("UTF8");
        sipHashMD.update(msg);
        final long digest = ((SipHashMD) sipHashMD).digestLong();
        assertEquals(0x726fdb47dd0e0e31L, digest);
    }

    @Test
    public void oneByte() throws Exception {
        final byte[] msg = "a".getBytes("UTF8");
        sipHashMD.update(msg);
        final long digest = ((SipHashMD) sipHashMD).digestLong();
        assertEquals(0x2ba3e8e9a71148caL, digest);
    }

    @Test
    public void sixBytes() throws Exception {
        final byte[] msg = "abcdef".getBytes("UTF8");
        sipHashMD.update(msg);
        final long digest = ((SipHashMD) sipHashMD).digestLong();
        assertEquals(0x2a6e77e733c7c05dL, digest);
    }

    @Test
    public void sixBytes2() throws Exception {
        final byte[] msg0 = "ab".getBytes("UTF8");
        final byte[] msg1 = "cdef".getBytes("UTF8");
        sipHashMD.update(msg0);
        sipHashMD.update(msg1);
        final long digest = ((SipHashMD) sipHashMD).digestLong();
        assertEquals(0x2a6e77e733c7c05dL, digest);
    }

    @Test
    public void sevenBytes() throws Exception {
        final byte[] msg = "SipHash".getBytes("UTF8");
        sipHashMD.update(msg);
        final long digest = ((SipHashMD) sipHashMD).digestLong();
        assertEquals(0x8325093242a96f60L, digest);
    }

    @Test
    public void eightBytes() throws Exception {
        final byte[] msg = "12345678".getBytes("UTF8");
        sipHashMD.update(msg);
        final long digest = ((SipHashMD) sipHashMD).digestLong();
        assertEquals(0x2130609caea37ebL, digest);
    }

    @Test
    public void oneMillionZeroBytes() throws Exception {
        for (int i = 0; i < 1000; i++) {
            final byte[] msg = Utils.byteTimes(0, 1000);
            sipHashMD.update(msg);
        }
        final long digest = ((SipHashMD) sipHashMD).digestLong();
        assertEquals(0x28205108397aa742L, digest);
    }

}
