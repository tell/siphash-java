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

import java.security.MessageDigest;
import java.util.ArrayDeque;
import java.util.Arrays;

/**
 * @author Tadanori TERUYA &lt;tadanori.teruya@gmail.com&gt; (2012)
 */
public class SipHashMD extends MessageDigest {

    private SipKey sipKey;
    private InnerState innerState;

    protected SipHashMD(String s) {
        super("SipHash-2-4");
    }

    public void setSipKey(final SipKey sipKey) {
        this.sipKey = sipKey;
        this.innerState = new InnerState();
    }

    public SipKey getSipKey() {
        return sipKey;
    }

    @Override
    protected void engineUpdate(byte b) {
        innerState.add(b);
    }

    @Override
    protected void engineUpdate(byte[] bytes, int i, int i2) {
        final byte[] copied = Arrays.copyOfRange(bytes, i, i2);
        innerState.add(copied);
    }

    @Override
    protected byte[] engineDigest() {
        final byte[] result = new byte[bytesPerLong];
        UnsignedInt64.intToBin(digestLong(), result);
        return result;
    }

    public long digestLong() {
        final long result = innerState.doFinalize();
        innerState = new InnerState();
        return result;
    }

    @Override
    protected void engineReset() {
        this.innerState = new InnerState();
    }

    public static final int bytesPerLong = 8;
    public static final int modulusOfByteCounter = 256;
    public static final int sipHashC = 2;
    public static final int sipHashD = 4;
    public static final long constantFF = 0xffL;

    private class InnerState {
        private int byteCounter;
        private final ArrayDeque<Byte> byteQueue;
        private long v0;
        private long v1;
        private long v2;
        private long v3;

        public InnerState() {
            byteCounter = 0;
            byteQueue = new ArrayDeque<Byte>();
            v0 = 0x736f6d6570736575L ^ sipKey.getLeftHalf();
            v1 = 0x646f72616e646f6dL ^ sipKey.getRightHalf();
            v2 = 0x6c7967656e657261L ^ sipKey.getLeftHalf();
            v3 = 0x7465646279746573L ^ sipKey.getRightHalf();
        }

        public void add(final byte b) {
            byteQueue.addLast(b);
            byteCounter += 1;
            byteCounter %= modulusOfByteCounter;

            if (byteQueue.size() > bytesPerLong - 1) {
                doRoundTimes(byteQueue.size() / bytesPerLong);
            }
        }

        public void add(final byte[] bytes) {
            for (final byte b : bytes) {
                byteQueue.addLast(b);
            }
            byteCounter += bytes.length;
            byteCounter %= modulusOfByteCounter;

            if (byteQueue.size() > bytesPerLong - 1) {
                doRoundTimes(byteQueue.size() / bytesPerLong);
            }
        }

        private void sipRound() {
            v0 += v1;
            v2 += v3;
            v1 = UnsignedInt64.rotateLeft(v1, 13);
            v3 = UnsignedInt64.rotateLeft(v3, 16);
            v1 ^= v0;
            v3 ^= v2;
            v0 = UnsignedInt64.rotateLeft(v0, 32);
            v2 += v1;
            v0 += v3;
            v1 = UnsignedInt64.rotateLeft(v1, 17);
            v3 = UnsignedInt64.rotateLeft(v3, 21);
            v1 ^= v2;
            v3 ^= v0;
            v2 = UnsignedInt64.rotateLeft(v2, 32);
        }

        private long extract() {
            final byte[] messageBlock = new byte[bytesPerLong];
            for (int j = 0; j < bytesPerLong; j++) {
                messageBlock[j] = byteQueue.pollFirst();
            }
            return UnsignedInt64.binToInt(messageBlock);
        }

        private void doRound(final long message) {
            v3 ^= message;
            for (int j = 0; j < sipHashC; j++) {
                sipRound();
            }
            v0 ^= message;
        }

        private void doRoundTimes(final int numberOfBlocks) {
            for (int i = 0; i < numberOfBlocks; i++) {
                doRound(extract());
            }
        }

        private long extractFinalBlock() {
            final int size = byteQueue.size();
            assert size < 8;
            long result = 0L;
            for (int i = 0; i < size; i++) {
                result <<= 8;
                result |= ((long) byteQueue.pollLast());
            }
            result |= ((long) byteCounter) << 56;
            return result;
        }

        public long doFinalize() {
            doRound(extractFinalBlock());
            v2 ^= constantFF;
            for (int i = 0; i < sipHashD; i++) {
                sipRound();
            }
            return v0 ^ v1 ^ v2 ^ v3;
        }
    }
}
