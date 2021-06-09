/*
 * MIT License
 *
 * Copyright (c) 2021 APIS Point, LLC.
 *
 */
package com.apispoint.cryptocurrency.coldstorage;

import java.security.MessageDigest;
import java.util.Arrays;

//
// Methods below adopted from bitcoinj (https://github.com/bitcoinj/bitcoinj)
//    divmod
//    encodeBase58
//
public final class Encode58 {

    private Encode58() {}

    private static final char[] ALPHABET     = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".toCharArray();
    private static final char   ENCODED_ZERO = ALPHABET[0];

    private static byte divmod(byte[] number, int firstDigit, int base, int divisor) {
        // this is just long division which accounts for the base of the input digits
        int remainder = 0;
        for (int i = firstDigit; i < number.length; i++) {
            int digit = (int) number[i] & 0xFF;
            int temp = remainder * base + digit;
            number[i] = (byte) (temp / divisor);
            remainder = temp % divisor;
        }
        return (byte) remainder;
    }

    private static String encodeBase58(byte[] input) {
        if (input.length == 0) {
            return "";
        }       
        // Count leading zeros.
        int zeros = 0;
        while (zeros < input.length && input[zeros] == 0) {
            ++zeros;
        }
        // Convert base-256 digits to base-58 digits (plus conversion to ASCII characters)
        input = Arrays.copyOf(input, input.length); // since we modify it in-place
        char[] encoded = new char[input.length * 2]; // upper bound
        int outputStart = encoded.length;
        for (int inputStart = zeros; inputStart < input.length; ) {
            encoded[--outputStart] = ALPHABET[divmod(input, inputStart, 256, 58)];
            if (input[inputStart] == 0) {
                ++inputStart; // optimization - skip leading zeros
            }
        }
        // Preserve exactly as many leading encoded zeros in output as there were leading zeros in input.
        while (outputStart < encoded.length && encoded[outputStart] == ENCODED_ZERO) {
            ++outputStart;
        }
        while (--zeros >= 0) {
            encoded[--outputStart] = ENCODED_ZERO;
        }
        // Return encoded string (including encoded leading zeros).
        return new String(encoded, outputStart, encoded.length - outputStart);
    }

    public static String base58Check(byte[] payload, byte version, MessageDigest sha) {
        byte[] vp = new byte[payload.length + 1];
        System.arraycopy(payload, 0, vp, 1, payload.length);
        vp[0] = version;

        byte[] checksum = sha.digest(sha.digest(vp));

        byte[] vpc = new byte[vp.length + 4]; // 4 bytes for the checksum
        System.arraycopy(vp, 0, vpc, 0, vp.length);
        System.arraycopy(checksum, 0, vpc, vp.length, 4);

        return encodeBase58(vpc);
    }

}
