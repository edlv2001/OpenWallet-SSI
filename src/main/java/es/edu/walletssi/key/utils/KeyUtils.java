package es.edu.walletssi.key.utils;

import com.google.crypto.tink.subtle.Hex;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.util.Base64URL;
import es.edu.walletssi.key.KeyHandlerEd25519;
import es.edu.walletssi.model.exception.UnsupportedKeyAlgorithm;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;

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
            return publicKeyRSAToJWK(publicKey.getEncoded());
        }
        if(publicKey.getAlgorithm().equals("other")){
            return null;
        }
        throw new UnsupportedKeyAlgorithm("The key type " + publicKey.getAlgorithm() + " is not supported");
    }

    private static JWK publicKeyRSAToJWK(byte[] publicKeyBytes) {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
            RSAPublicKey publicKey = (RSAPublicKey) keyFactory.generatePublic(keySpec);

            JWK jwk = new RSAKey.Builder(publicKey)
                    .build();

            return jwk;
        } catch (Exception e){
            throw new RuntimeException();
        }
    }

    private static OctetKeyPair publicKeyEC25519ToJwk(PublicKey publicKey){
        OctetKeyPair jwk = null;
        String kid = KeyUtils.kidGenerator(publicKey);

        OctetKeyPair.Builder builder = new OctetKeyPair.Builder(Curve.Ed25519, Base64URL.encode(publicKey.getEncoded()));
        jwk = builder
                .keyID(kid)
                .keyUse(KeyUse.SIGNATURE)
                .build();

        return jwk;
    }


    public static PublicKey publicJwkToKeyEC25519(OctetKeyPair okp){
        byte[] decoded = okp.getDecodedX();
        return new KeyHandlerEd25519.PublicKeyEd25519(decoded);
    }

}
