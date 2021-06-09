/*
 * MIT License
 *
 * Copyright (c) 2021 APIS Point, LLC.
 *
 */
package com.apispoint.cryptocurrency.coldstorage;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPoint;

import org.bouncycastle.crypto.fips.FipsStatus;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.bouncycastle.util.encoders.Hex;

public final class Wallet {

    private Wallet() {}

    private static String padTo64(String s) {
        if(s.length() < 62 || s.length() > 64)
            throw new IllegalArgumentException("Invalid key: " + s);

        while(s.length() < 64)
            s = "0" + s;

        return s;
    }

    private static KeyPair getKeyPair(KeyPairGenerator keyGen, SecureRandom random) throws Exception{
        ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256k1");
        keyGen.initialize(ecSpec, random);

        return keyGen.generateKeyPair();
    }

    private static void btc(KeyPair kp, MessageDigest sha, MessageDigest rmd) throws Exception {
        PublicKey  pub = kp.getPublic();
        PrivateKey pvt = kp.getPrivate();

        //
        // Private Key
        //
        ECPrivateKey epvt = (ECPrivateKey) pvt;
        String sepvt = padTo64(epvt.getS().toString(16));
        System.out.println("s[" + sepvt.length() + "]: " + sepvt);

        String cwif = Encode58.base58Check(Hex.decode(sepvt + "01"), (byte) 0x80, sha);
        System.out.println("  wif: " + cwif);

        //
        // Public Key
        //
        ECPublicKey epub = (ECPublicKey) pub;
        ECPoint pt = epub.getW();
        String sx = padTo64(pt.getAffineX().toString(16));

        //
        // Compressed bcPub
        //
        BigInteger _sy = pt.getAffineY();
        String cbcPub = (_sy.and(BigInteger.ONE).intValue() == 0 ? "02" : "03") + sx;

        byte[] s1 = sha.digest(Hex.decode(cbcPub));
        byte[] r1 = rmd.digest(s1);

        String adr = Encode58.base58Check(r1, (byte) 0x00, sha);
        System.out.println("  adr: " + adr);
    }

    private static void providerOK(String obj, Provider provider, String expectation) {
        String  p_str = provider.toString();
        boolean p_sts = p_str.contains(expectation);

        System.out.println(String.format("[%s] %s=%s", p_sts ? "ok" : "panic", obj, p_str));

        if(p_sts == false)
            System.exit(-2);
    }

    public static void main(String[] args) throws Exception {
        String provider = "BCFIPS";
        Security.addProvider(new BouncyCastleFipsProvider());

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC",     provider);
        SecureRandom     random = SecureRandom.getInstance("DEFAULT",    provider);
        MessageDigest    sha    = MessageDigest.getInstance("SHA-256",   provider);
        MessageDigest    rmd    = MessageDigest.getInstance("RipeMD160", provider);

        boolean isFipsReady = FipsStatus.isReady();
        System.out.println((isFipsReady ? "[ok]" : "[panic]") + " FIPS ready");
        if(isFipsReady == false)
            System.exit(-1);

        providerOK("key_provider", keyGen.getProvider(), provider);
        providerOK("rng_provider", random.getProvider(), provider);
        providerOK("sha_provider",    sha.getProvider(), provider);
        providerOK("rmd_provider",    rmd.getProvider(), provider);

        System.out.println("\nBTC");
        btc(getKeyPair(keyGen, random), sha, rmd);
    }

}
