package org.example.walletssi.model.vc;

import com.danubetech.verifiablecredentials.VerifiableCredential;
import com.danubetech.verifiablecredentials.VerifiablePresentation;
import org.didcommx.didcomm.diddoc.DIDDoc;
import org.didcommx.didcomm.diddoc.DIDDocResolver;
import org.didcommx.didcomm.diddoc.VerificationMethod;
import org.example.walletssi.model.DidMethod;
import org.example.walletssi.model.didUtils.DIDParser;
import org.example.walletssi.model.handlers.config.DidMethodHandlerConfig;
import org.example.walletssi.model.vc.signature.VerifySignature;

import static org.example.walletssi.model.vc.VerifiableCredentialVerifier.validateSchema;

public class VerifiablePresentationVerifier {
    public boolean verify(String vp, DidMethodHandlerConfig config, boolean fromTrustedRegistry){
        VerifiablePresentation presentation = VerifiablePresentation.fromJson(vp);
        return verify(presentation, config, fromTrustedRegistry);
    }

    public boolean verify(VerifiablePresentation vp, DidMethodHandlerConfig config, boolean fromTrustedRegistry){
        String schemaRegistry = (DidMethod.getHandler(DIDParser.parseDID(vp.getHolder().toString()), config)).getSchemaRegistry();
        if(!validateSchema(schemaRegistry, vp, fromTrustedRegistry))
            return false;
        return verifyWithoutRegistry(vp, config);
    }

    public boolean verifyWithoutRegistry(String vp, DidMethodHandlerConfig config){
        VerifiablePresentation presentation = VerifiablePresentation.fromJson(vp);
        return verifyWithoutRegistry(presentation, config);
    }

    public boolean verifyWithoutRegistry(VerifiablePresentation presentation, DidMethodHandlerConfig config){
        VerifiableCredential credential = presentation.getVerifiableCredential();

        VerifiableCredentialVerifier verifier = new VerifiableCredentialVerifier();
        if(!verifier.verifyWithoutRegistry(credential, config))
            return false;
        return verifyOnlyPresentation(presentation, config);

    }

    private boolean verifyOnlyPresentation(VerifiablePresentation presentation, DidMethodHandlerConfig config){
        String did = presentation.getHolder().toString();
        DidMethod didMethod = DIDParser.parseDID(did);

        DIDDocResolver resolver = DidMethod.getResolver(didMethod, config);

        DIDDoc doc = resolver.resolve(did).orElse(null);
        if(doc == null)
            return false;

        VerifiablePresentation presentation1 = VerifiablePresentation.builder().ldProof(presentation.getLdProof()).build();

        for(VerificationMethod v: doc.getVerificationMethods()){
            if(VerifySignature.tryVerify(v, presentation))
                return true;
        }
        return false;
    }


    public boolean verifyWithOnlyVCSchema(String vp, DidMethodHandlerConfig config, boolean fromTrustedRegistry){
        VerifiablePresentation presentation = VerifiablePresentation.fromJson(vp);
        VerifiableCredential credential = presentation.getVerifiableCredential();
        VerifiableCredentialVerifier verifier = new VerifiableCredentialVerifier();
        if(!verifier.verify(credential, config, fromTrustedRegistry))
            return false;
        return verifyOnlyPresentation(presentation, config);
    }

}
