package com.github.emboss.siphash;

import java.security.Key;

/**
 * @author <a href="mailto:Martin.Bosslet@googlemail.com">Martin Bosslet</a>
 */
public class SipKey implements Key {
    private final byte[] key;

    public SipKey(byte[] key) {
        if (key == null || key.length != 16)
            throw new RuntimeException("SipHash key must be 16 bytes");
        this.key = key;
    }

    long getLeftHalf() {
        return UnsignedInt64.binToIntOffset(key, 0);
    }

    long getRightHalf() {
        return UnsignedInt64.binToIntOffset(key, 8);
    }

    @Override
    public String getAlgorithm() {
        return "SipHash-2-4";
    }

    @Override
    public String getFormat() {
        return null;  //To change body of implemented methods use File | Settings | File Templates.
    }

    @Override
    public byte[] getEncoded() {
        return key;
    }
}
