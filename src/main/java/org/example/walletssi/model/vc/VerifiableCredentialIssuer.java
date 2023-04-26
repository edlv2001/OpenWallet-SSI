package org.example.walletssi.model.vc;

import com.danubetech.verifiablecredentials.CredentialSubject;
import com.danubetech.verifiablecredentials.VerifiableCredential;
import org.example.walletssi.key.KeyHandler;

import java.net.URI;
import java.security.KeyPair;
import java.util.Date;
import java.util.Map;

public class VerifiableCredentialIssuer {
    private KeyHandler keyHandler;

    public VerifiableCredentialIssuer(KeyHandler keyHandler){
        this.keyHandler = keyHandler;
    }

    public String issue(Map<String, Object> claims, String didIssuer, String didHolder, KeyPair keyPair, Date expirationDate){
        CredentialSubject credentialSubject = CredentialSubject.builder()
                .claims(claims)
                .id(URI.create(didHolder))
                .build();

        VerifiableCredential vc = VerifiableCredential.builder()
                .credentialSubject(credentialSubject)
                .expirationDate(expirationDate)
                .build();



        return vc.toJson();
    }

}
