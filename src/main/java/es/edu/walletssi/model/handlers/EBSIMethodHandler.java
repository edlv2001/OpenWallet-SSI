package es.edu.walletssi.model.handlers;

import es.edu.walletssi.key.utils.KeyUtils;
import es.edu.walletssi.model.handlers.config.EBSIMethodHandlerConfig;
import foundation.identity.did.DIDDocument;
import foundation.identity.did.VerificationMethod;
import foundation.identity.jsonld.JsonLDObject;
import io.ipfs.multibase.Multibase;
import org.didcommx.didcomm.diddoc.DIDDocResolver;

import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.URI;
import java.security.*;
import java.util.*;

import com.nimbusds.jose.jwk.*;
import es.edu.walletssi.model.resolver.EBSIDIDDocResolver;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;


public class EBSIMethodHandler implements DidMethodHandler {
    public final String ebsi;

    private String didRegistry = "http://localhost:8080";

    private String schemaRegistry = "http://localhost:8080";

    private File dir;

    private DIDDocResolver resolver;


    //CONSTRUCTORS
    public EBSIMethodHandler(EBSIMethodHandlerConfig config){
        this.ebsi = config.getEbsiMethod();
        if(!ebsi.matches("ebsi[A-Za-z0-9]*")){
            throw new IllegalArgumentException("Invalid EBSI network name. Must start with \"ebsi\".");
        }
        this.dir = new File(config.getDidStorePath());
        if(!this.dir.isDirectory())
            this.dir.mkdirs();
        if(!dir.canRead() || !dir.canWrite()){
            throw new IllegalArgumentException("Sin permisos necesarios para usar el directorio " + dir);
        }
        resolver = new EBSIDIDDocResolver(config);
    }

    public EBSIMethodHandler(EBSIMethodHandlerConfig config, boolean aux){
        this.ebsi = config.getEbsiMethod();
        if(!ebsi.matches("ebsi[A-Za-z0-9]*")){
            throw new IllegalArgumentException("Invalid EBSI network name. Must start with \"ebsi\".");
        }
        this.dir = new File(config.getDidStorePath());
    }

    //OVERRIDEN METHODS
    @Override
    public String getDIDMethod(){
        return ebsi;
    }

    @Override
    public DIDDocResolver getResolver() {
        return resolver;
    }

    @Override
    public String getDIDRegistry() {
        return didRegistry;
    }

    public Class<?> getConfigClass(){ return EBSIMethodHandlerConfig.class; }

    public String getSchemaRegistry(){ return schemaRegistry; }

    @Override
    public String genDID(PublicKey publicKey){
        String did = "did:ebsi:" + Multibase.encode(Multibase.Base.Base58BTC, ebsiSubject());

        String didDoc = generateDidDocument(did, publicKey);


        if(registerDID(did, didDoc)){
            storeDID(did, didDoc);
            return did;
        }

        throw new RuntimeException("No se ha podido registrar el DID");



    }

    private byte[] ebsiSubject(){
        byte[] bytes = new byte[17];
        new SecureRandom().nextBytes(bytes);
        bytes[0] = 1;
        return bytes;
    }

    private String generateDidDocument(String did, PublicKey publicKey){
        VerificationMethod method = null;

        JWK jwk = KeyUtils.publicKeyToJWK(publicKey);

        String id = did + "#" + KeyUtils.getJWKThumbprint(jwk);
        try {
            method = VerificationMethod.builder()
                    .publicKeyJwk(jwk.toJSONObject())
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

    public boolean registerDID(String did, String didDocument){
        RestTemplate restTemplate = new RestTemplate();
        ResponseEntity<Boolean> response =
                restTemplate.postForEntity(didRegistry + "/register?did=" + did, didDocument, Boolean.class, (Object) null);
        return response.getBody().booleanValue();
    }

    @Override
    public File getDir() {
        return dir;
    }

    public Object getKeyIdFromDIDDoc(DIDDocument didDoc){
        return didDoc.getVerificationMethods().get(0).getPublicKeyJwk().get("kid");
    }

    public void storeDID(String did, String didDoc){
        did = did.replaceFirst(":", "%3");
        did = did.replaceFirst(":", "%3");
        File file = new File(getDir(), did);
        if(file.exists()){
            throw new IllegalArgumentException("DID already exists");
        }
        try {
            file.createNewFile();
            PrintWriter pw = new PrintWriter(file);
            pw.print(didDoc);
            pw.close();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }


}
