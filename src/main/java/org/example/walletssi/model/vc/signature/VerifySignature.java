package org.example.walletssi.model.vc.signature;

import com.danubetech.verifiablecredentials.VerifiableCredential;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetKeyPair;
import foundation.identity.jsonld.JsonLDObject;
import info.weboftrust.ldsignatures.verifier.Ed25519Signature2020LdVerifier;
import info.weboftrust.ldsignatures.verifier.LdVerifier;
import info.weboftrust.ldsignatures.verifier.RsaSignature2018LdVerifier;
import org.didcommx.didcomm.common.VerificationMaterialFormat;
import org.didcommx.didcomm.diddoc.VerificationMethod;
import org.example.walletssi.key.utils.KeyUtils;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;

public class VerifySignature {

    public static boolean tryAllSignatureMethodLD(VerifiableCredential vc, PublicKey publicKey){
        LdVerifier ldVerifier;

        //ED25519
        ldVerifier = new Ed25519Signature2020LdVerifier(publicKey.getEncoded());
        try {
            if(ldVerifier.verify(vc, vc.getLdProof()))
                return true;
        } catch (Exception e) {}


        //RSA
        try {
            // Convierte la clave pública a partir del arreglo de bytes
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKey.getEncoded());
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PublicKey publicKey2 = keyFactory.generatePublic(keySpec);

            if (publicKey2 instanceof RSAPublicKey) {
                RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey2;
                ldVerifier = new RsaSignature2018LdVerifier(rsaPublicKey);
                return ldVerifier.verify(vc, vc.getLdProof());
            }
        } catch (Exception e) {}

        // ADD MORE



        //

        return false;
    }


    public static boolean tryVerify(VerificationMethod v, JsonLDObject credential){
        VerificationMaterialFormat format = v.getVerificationMaterial().getFormat();
        switch(format){
            case JWK -> {
                try {
                    JWK jwk = JWK.parse(v.getVerificationMaterial().getValue());
                    return verifyJWK(jwk, credential);
                } catch (ParseException e) {
                    throw new RuntimeException(e);
                }
            }


        }
        return false;
    }

    public static boolean verifyJWK(JWK jwk, JsonLDObject credential){
        try {
            OctetKeyPair okp = jwk.toOctetKeyPair();
            PublicKey key = KeyUtils.publicJwkToKeyEC25519(okp);

            Ed25519Signature2020LdVerifier verifier = new Ed25519Signature2020LdVerifier(key.getEncoded());
            return verifier.verify(credential);
        } catch (Exception e) {System.out.println(e.getMessage());}
        try {
            RSAPublicKey publicKey = jwk.toRSAKey().toRSAPublicKey();

            RsaSignature2018LdVerifier verifier = new RsaSignature2018LdVerifier(publicKey);
            return verifier.verify(credential);
        } catch (Exception e) {}
        return false;
    }
}
