package org.example.walletssi.model.handlers;

import com.nimbusds.jose.util.Base64URL;
import foundation.identity.did.DIDDocument;
import foundation.identity.did.VerificationMethod;
import foundation.identity.jsonld.JsonLDObject;
import io.ipfs.multibase.Multibase;
import org.bouncycastle.jcajce.provider.digest.SHA256;
import org.example.walletssi.key.KeyHandlerEd25519;
import org.example.walletssi.model.DidMethodHandler;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;

import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.gen.*;
import org.example.walletssi.model.didUtils.DIDParser;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;


/**
 * <p>Implementation of DidMethodHandler designed to create and use EBSI
 * compliant DIDs.</p>
 * <p>This class only handles Legal Entities' EBSI DIDs,
 * since Natural Person's have become legacy, and did:key is used nowadays</p>
 * @see DidMethodHandler
 * @author Eduardo de la Vega
 */
public class EBSIMethodHandler implements DidMethodHandler {
    public final String ebsi;

    private String didRegistry = "localhost:9090";

    public EBSIMethodHandler(){
        ebsi = "ebsi";
    }

    public EBSIMethodHandler( String ebsi){
        if(!ebsi.matches("ebsi[A-Za-z0-9]*")){
            throw new IllegalArgumentException("Invalid EBSI network");
        }
        this.ebsi = ebsi;
    }

    public String genDID(PublicKey publicKey){
        String did = "did:ebsi:" + Multibase.encode(Multibase.Base.Base58BTC, ebsiSubject());
        //System.out.println(generateDidDocument(did, (KeyHandlerEd25519.PublicKeyEd25519) publicKey));
        return did;
    }

    private OctetKeyPair publicKeyToJwk(KeyHandlerEd25519.PublicKeyEd25519 publicKey){
        // Generate Ed25519 Octet key pair in JWK format, attach some metadata
        OctetKeyPair jwk = null;
        System.out.println(Arrays.toString(publicKey.getEncoded()));
        OctetKeyPair.Builder builder = new OctetKeyPair.Builder(Curve.Ed25519, Base64URL.encode(publicKey.getEncoded()));
        jwk = builder
                .keyUse(KeyUse.SIGNATURE)
                .build();

        // Output the private and public OKP JWK parameters
        System.out.println(jwk);

        // Output the public OKP JWK parameters only
        try {
            //System.out.println(Arrays.toString(jwk.toPublicJWK().toPublicKey().getEncoded()));
            OctetKeyPair ocp = OctetKeyPair.parse(jwk.toJSONString());
            System.out.println(Arrays.toString(ocp.getDecodedX()));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        //return jwk.toPublicJWK().toJSONString();
        return jwk;
    }

    private byte[] ebsiSubject(){
        byte[] bytes = new byte[17];
        new SecureRandom().nextBytes(bytes);
        bytes[0] = 1;
        return bytes;
    }

    private String generateDidDocument(String did, KeyHandlerEd25519.PublicKeyEd25519 publicKeyEd25519){
        VerificationMethod method = null;
        OctetKeyPair oKP = publicKeyToJwk(publicKeyEd25519);
        String id = did + "#" +getJWKThumbprint(oKP);
        try {
            method = VerificationMethod.builder()
                    .publicKeyJwk(oKP.toJSONObject())
                    .id(URI.create(id))
                    .type("JsonWebKey2020")
                    .controller(did)
                    .build();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        DIDDocument didDocument = DIDDocument.builder().
                context(URI.create("https://w3id.org/security/suites/jws-2020/v1")).
                id(URI.create(did)).
                verificationMethod(method).

                build();
        Map<String, Object> m = didDocument.toMap();
        List<String> list = new ArrayList<>(1);
        list.add(id);
        m.put("authentication",list);
        m.put("assertionMethod", list);

        return JsonLDObject.fromJsonObject(m).toJson(true);
    }


    private String getJWKThumbprint(OctetKeyPair okp){
        MessageDigest md = null;
        try {
            md = SHA256.Digest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        byte[] hash = md.digest(okp.toJSONString().getBytes(StandardCharsets.UTF_8));
        return Base64URL.encode(hash).toString();
    }

    private void saveDID(String did, String path){

    }


    public void registerDID(String did, String didDocument){

    }

    public DIDDocument resolveDID(String did){
        if(!DIDParser.isValid(did, org.example.walletssi.model.DidMethod.EBSI)){
            return null;
        }
        RestTemplate restTemplate = new RestTemplate();
        ResponseEntity<String> response = restTemplate.postForEntity(didRegistry, did, String.class);
        if(response == null || response.getBody() == null || response.getBody().isEmpty()){
            return null;
        }

        DIDDocument didDocument = DIDDocument.fromJson(response.getBody());
        return didDocument;
    }

}
