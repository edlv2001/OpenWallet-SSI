package es.edu.walletssi.model.vc.signature;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetKeyPair;
import es.edu.walletssi.key.utils.KeyUtils;
import es.edu.walletssi.model.didUtils.DIDDocImp;
import foundation.identity.jsonld.JsonLDObject;
import info.weboftrust.ldsignatures.verifier.Ed25519Signature2020LdVerifier;
import info.weboftrust.ldsignatures.verifier.RsaSignature2018LdVerifier;
import org.didcommx.didcomm.common.VerificationMaterialFormat;
import org.didcommx.didcomm.diddoc.DIDDoc;
import org.didcommx.didcomm.diddoc.VerificationMethod;

import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;

public class VerifySignature {

    /*
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
            // Convierte la clave pública a partir del array de bytes
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
*/

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

            //Soporte a otros métodos de clave

        }
        return false;
    }

    public static boolean verifyJWK(JWK jwk, JsonLDObject credential){
        try {
            OctetKeyPair okp = jwk.toOctetKeyPair();
            PublicKey key = KeyUtils.publicJwkToKeyEC25519(okp);

            Ed25519Signature2020LdVerifier verifier = new Ed25519Signature2020LdVerifier(key.getEncoded());
            return verifier.verify(credential);
        } catch (Exception e) {}
        try {
            RSAPublicKey publicKey = jwk.toRSAKey().toRSAPublicKey();

            RsaSignature2018LdVerifier verifier = new RsaSignature2018LdVerifier(publicKey);
            return verifier.verify(credential);
        } catch (Exception e) {}
        //añadir otros tipos de clave a futuro
        return false;
    }

    public static boolean verifyJsonLD(String did, JsonLDObject jsonLDObject, String didDoc){
        DIDDocImp didDocImp = DIDDocImp.Companion.fromJson(didDoc);
        DIDDoc doc = new DIDDoc(didDocImp.getDid(), didDocImp.getKeyAgreements(), didDocImp.getAuthentications(), didDocImp.getVerificationMethods(), didDocImp.getDidCommServices());
        if(!doc.getDid().equals(did))
            return false;


        for(VerificationMethod v: doc.getVerificationMethods()){
            if(VerifySignature.tryVerify(v, jsonLDObject))
                return true;
        }
        return false;
    }
}
