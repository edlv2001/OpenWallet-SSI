package org.example.walletssi.key.utils;

import com.google.crypto.tink.subtle.Hex;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.util.Base64URL;
import org.bouncycastle.jcajce.provider.digest.SHA256;
import org.example.walletssi.key.KeyHandlerEd25519;
import org.example.walletssi.model.exception.UnsupportedKeyAlgorithm;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Base64;

public class KeyUtils {
    public static byte[] hashSHA256(byte[] input){
        MessageDigest sha256 = null;
        try {
            sha256 = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        return sha256.digest(input);
    }

    public static String kidGenerator(Key key){
        return Hex.encode(hashSHA256(key.getEncoded()));
    }

    public static String getJWKThumbprint(JWK jwk){
        return Base64URL.encode(hashSHA256(jwk.toJSONString().getBytes(StandardCharsets.UTF_8))).toString();
    }

    public static JWK publicKeyToJWK(PublicKey publicKey){
        if(publicKey.getAlgorithm().equals("EC")){
            return publicKeyEC25519ToJwk(publicKey);
        }
        if(publicKey.getAlgorithm().equals("RSA")){
            return null;
        }
        if(publicKey.getAlgorithm().equals("other")){
            return null;
        }
        throw new UnsupportedKeyAlgorithm("The key type " + publicKey.getAlgorithm() + " is not supported");
    }

    private static OctetKeyPair publicKeyEC25519ToJwk(PublicKey publicKey){
        // Generate Ed25519 Octet key pair in JWK format, attach some metadata
        OctetKeyPair jwk = null;
        String kid = KeyUtils.kidGenerator(publicKey);
        System.out.println(Arrays.toString(publicKey.getEncoded()));

        OctetKeyPair.Builder builder = new OctetKeyPair.Builder(Curve.Ed25519, Base64URL.encode(publicKey.getEncoded()));
        jwk = builder
                .keyID(kid)
                .keyUse(KeyUse.SIGNATURE)
                .build();


        try {
            //System.out.println(Arrays.toString(jwk.toPublicJWK().toPublicKey().getEncoded()));
            OctetKeyPair ocp = OctetKeyPair.parse(jwk.toJSONString());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        //return jwk.toPublicJWK().toJSONString();
        return jwk;
    }


    public static PublicKey publicJwkToKeyEC25519(OctetKeyPair okp){
        PublicKey publicKey;
        byte[] decoded = okp.getDecodedX();
        return new KeyHandlerEd25519.PublicKeyEd25519(decoded);
    }

}
