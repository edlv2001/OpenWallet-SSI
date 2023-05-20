package org.example.walletssi.model.vc;

import com.danubetech.keyformats.crypto.ByteSigner;
import com.danubetech.keyformats.crypto.impl.Ed25519_EdDSA_PrivateKeySigner;
import com.danubetech.verifiablecredentials.CredentialSubject;
import com.danubetech.verifiablecredentials.VerifiableCredential;
import com.danubetech.verifiablecredentials.jwt.JwtVerifiableCredential;
import com.danubetech.verifiablecredentials.jwt.ToJwtConverter;
import com.nimbusds.jose.JOSEException;
import foundation.identity.did.DIDDocument;
import foundation.identity.jsonld.JsonLDException;
import info.weboftrust.ldsignatures.LdProof;
import info.weboftrust.ldsignatures.jsonld.LDSecurityKeywords;
import info.weboftrust.ldsignatures.signer.*;
import org.example.walletssi.key.KeyHandler;
import org.example.walletssi.model.didUtils.DIDDocUtils;
import org.example.walletssi.model.vc.signature.Signature;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Date;
import java.util.Map;

public class VerifiableCredentialIssuer {
    private KeyHandler keyHandler;

    public VerifiableCredentialIssuer(){
    }

    public VerifiableCredential issue(Map<String, Object> claims, String didIssuer, String didHolder, KeyPair keyPair, Date expirationDate){
        CredentialSubject credentialSubject = CredentialSubject.builder()
                .claims(claims)
                .id(URI.create(didHolder))
                .build();



        VerifiableCredential vc = VerifiableCredential.builder()
                .issuer(URI.create(didIssuer))
                .credentialSubject(credentialSubject)
                .expirationDate(expirationDate)
                .build();




        return vc;
    }


    public String signJWT(VerifiableCredential vc, KeyPair keyPair){


        byte[] signData = new byte[64];
        System.arraycopy(keyPair.getPrivate().getEncoded(), 0, signData, 0, 32);
        System.arraycopy(keyPair.getPublic().getEncoded(), 0, signData, 32, 32);
        ByteSigner byteSigner = new Ed25519_EdDSA_PrivateKeySigner(signData);

        JwtVerifiableCredential jwtVerifiableCredential = ToJwtConverter.toJwtVerifiableCredential(vc);
        String jwtPayload = jwtVerifiableCredential.getPayload().toString();
        System.out.println(jwtPayload);
        System.out.println(jwtVerifiableCredential.getCompactSerialization());
        String jwtString = null;
        try {
            //jwtString = jwtVerifiableCredential.sign_Ed25519_EdDSA(testEd25519PrivateKey);
            jwtString = jwtVerifiableCredential.sign_Ed25519_EdDSA(byteSigner);
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }
        return jwtString;
    }

    public String signVC(VerifiableCredential vc, KeyPair keyPair, String didIssuer, DIDDocument didIssuerDocument){
        return Signature.signJsonLD(vc, keyPair, didIssuer, didIssuerDocument);
    }




}
