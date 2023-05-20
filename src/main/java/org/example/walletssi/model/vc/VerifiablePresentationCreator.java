package org.example.walletssi.model.vc;

import com.danubetech.verifiablecredentials.VerifiableCredential;
import com.danubetech.verifiablecredentials.VerifiablePresentation;
import foundation.identity.did.DIDDocument;
import foundation.identity.jsonld.JsonLDException;
import info.weboftrust.ldsignatures.LdProof;
import info.weboftrust.ldsignatures.jsonld.LDSecurityKeywords;
import info.weboftrust.ldsignatures.signer.LdSigner;
import org.example.walletssi.model.didUtils.DIDDocUtils;
import org.example.walletssi.model.vc.signature.Signature;

import java.io.IOException;
import java.net.URI;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.util.Date;

public class VerifiablePresentationCreator {

    public VerifiablePresentation issueVP(String vc, String did){
        VerifiableCredentialVerifier verifier = new VerifiableCredentialVerifier();

        return VerifiablePresentation.builder()
                .verifiableCredential(VerifiableCredential.fromJson(vc))
                .holder(URI.create(did))
                .build();

    }

    public String signVP(VerifiablePresentation vp, KeyPair keyPair, String did, DIDDocument didDocument){
        return Signature.signJsonLD(vp, keyPair, did, didDocument);
    }
}
