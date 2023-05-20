package org.example.walletssi.model.vc.signature;

import com.danubetech.keyformats.crypto.ByteSigner;
import com.danubetech.keyformats.crypto.impl.Ed25519_EdDSA_PrivateKeySigner;
import foundation.identity.did.DIDDocument;
import foundation.identity.jsonld.JsonLDException;
import foundation.identity.jsonld.JsonLDObject;
import info.weboftrust.ldsignatures.LdProof;
import info.weboftrust.ldsignatures.jsonld.LDSecurityKeywords;
import info.weboftrust.ldsignatures.signer.Ed25519Signature2020LdSigner;
import info.weboftrust.ldsignatures.signer.JsonWebSignature2020LdSigner;
import info.weboftrust.ldsignatures.signer.LdSigner;
import info.weboftrust.ldsignatures.signer.RsaSignature2018LdSigner;
import org.example.walletssi.model.didUtils.DIDDocUtils;

import java.io.IOException;
import java.net.URI;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.util.Arrays;
import java.util.Date;

public class Signature {
    public static ByteSigner chooseByteSigner(String algorithm, KeyPair keyPair){
        if(algorithm.equals("EC"))
            return new Ed25519_EdDSA_PrivateKeySigner(keyPair.getPrivate().getEncoded());
        if(algorithm.equals("RSA"))
            return new com.danubetech.keyformats.crypto.impl.RSA_RS256_PrivateKeySigner(keyPair);
        if(algorithm.equals("JWS"))
            return new JsonWebSignature2020LdSigner().getSigner();
        return null;
    }

    public static LdSigner chooseSignerLD(String algorithm, KeyPair keyPair){
        if(algorithm.equals("EC")) {
            byte[] signData = new byte[64];
            System.arraycopy(keyPair.getPrivate().getEncoded(), 0, signData, 0, 32);
            System.arraycopy(keyPair.getPublic().getEncoded(), 0, signData, 32, 32);
            return new Ed25519Signature2020LdSigner(signData);
        }
        if(algorithm.equals("RSA"))
            return new RsaSignature2018LdSigner(keyPair);
        return null;
    }

    public static String signJsonLD(JsonLDObject object, KeyPair keyPair, String did, DIDDocument didDoc){
        int nKey = -1;
        if((nKey = DIDDocUtils.findKey(didDoc, keyPair.getPublic())) == -1)
            throw new IllegalArgumentException();
        byte[] signData = new byte[64];
        System.arraycopy(keyPair.getPrivate().getEncoded(), 0, signData, 0, 32);
        System.arraycopy(keyPair.getPublic().getEncoded(), 0, signData, 32, 32);
        LdSigner signer = Signature.chooseSignerLD(keyPair.getPublic().getAlgorithm(), keyPair);
        signer.setCreated(new Date());
        signer.setProofPurpose(LDSecurityKeywords.JSONLD_TERM_ASSERTIONMETHOD);
        signer.setVerificationMethod(URI.create(did + "#keys-" + nKey));

        try {
            LdProof ldProof = signer.sign(object);
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        } catch (JsonLDException e) {
            throw new RuntimeException(e);
        }
        return object.toJson(true);
    }
}
