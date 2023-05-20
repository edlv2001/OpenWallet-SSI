package org.example.walletssi.model.vc;

import com.danubetech.keyformats.crypto.ByteVerifier;
import com.danubetech.keyformats.crypto.impl.Ed25519_EdDSA_PrivateKeySigner;
import com.danubetech.keyformats.crypto.impl.Ed25519_EdDSA_PublicKeyVerifier;
import com.danubetech.verifiablecredentials.VerifiableCredential;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetKeyPair;
import foundation.identity.did.DIDDocument;
import foundation.identity.did.validation.Validation;
import foundation.identity.jsonld.JsonLDException;
import info.weboftrust.ldsignatures.verifier.Ed25519Signature2020LdVerifier;
import info.weboftrust.ldsignatures.verifier.LdVerifier;
import info.weboftrust.ldsignatures.verifier.RsaSignature2018LdVerifier;
import io.ipfs.multibase.Base58;
import org.didcommx.didcomm.common.VerificationMaterial;
import org.didcommx.didcomm.common.VerificationMaterialFormat;
import org.didcommx.didcomm.common.VerificationMethodType;
import org.didcommx.didcomm.diddoc.DIDDoc;
import org.didcommx.didcomm.diddoc.DIDDocResolver;
import org.didcommx.didcomm.diddoc.VerificationMethod;
import org.example.walletssi.key.utils.KeyUtils;
import org.example.walletssi.model.DidMethod;
import org.example.walletssi.model.didUtils.DIDDocImp;
import org.example.walletssi.model.didUtils.DIDDocUtils;
import org.example.walletssi.model.didUtils.DIDParser;
import org.example.walletssi.model.handlers.config.DidMethodHandlerConfig;
import org.example.walletssi.model.resolver.DIDResolver;
import org.example.walletssi.model.vc.signature.VerifySignature;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import java.util.List;

public class VerifiableCredentialVerifier {

    public boolean verify(String vc){
        //com.github.fge.jsonschema.main.JsonSchemaFactory.newBuilder().
        return false;
    }

    private String getSchema(String schema){
        return null;
    }

    public boolean verifyWithoutRegistry(String vc, DidMethodHandlerConfig config){
        VerifiableCredential credential = VerifiableCredential.fromJson(vc);
        return verifyWithoutRegistry(credential, config);
    }


    public boolean verifyWithoutRegistry(VerifiableCredential credential, DidMethodHandlerConfig config){
        String didIssuer = credential.getIssuer().toString();
        DidMethod didMethod = DIDParser.parseDID(didIssuer);

        DIDDocResolver resolver = DidMethod.getResolver(didMethod, config);

        DIDDoc doc = resolver.resolve(didIssuer).orElse(null);
        if(doc == null)
            return false;

        System.out.println(doc.toString());

        for(VerificationMethod v: doc.getVerificationMethods()){
            if(VerifySignature.tryVerify(v, credential))
                return true;
        }
        return false;
    }

}
