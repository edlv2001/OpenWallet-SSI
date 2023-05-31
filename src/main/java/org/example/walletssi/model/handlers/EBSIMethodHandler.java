package org.example.walletssi.model.handlers;

import foundation.identity.did.DIDDocument;
import foundation.identity.did.VerificationMethod;
import foundation.identity.jsonld.JsonLDObject;
import io.ipfs.multibase.Multibase;
import org.didcommx.didcomm.diddoc.DIDDocResolver;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.URI;
import java.security.*;
import java.util.*;
import java.util.function.Predicate;

import com.nimbusds.jose.jwk.*;
import org.example.walletssi.key.utils.KeyUtils;
import org.example.walletssi.model.didUtils.DIDParser;
import org.example.walletssi.model.handlers.config.DefaultMethodHandlerConfig;
import org.example.walletssi.model.handlers.config.DidMethodHandlerConfig;
import org.example.walletssi.model.handlers.config.EBSIMethodHandlerConfig;
import org.example.walletssi.model.resolver.EBSIDIDDocResolver;
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

    private String didRegistry = "http://localhost:8080";

    private String schemaRegistry = "http://localhost:8080";

    private File dir = new File("data/did/created");

    private DIDDocResolver resolver;


    //CONSTRUCTORS
    public EBSIMethodHandler(EBSIMethodHandlerConfig config){
        this.ebsi = config.getEbsiMethod();
        if(!ebsi.matches("ebsi[A-Za-z0-9]*")){
            throw new IllegalArgumentException("Invalid EBSI network name. Must start with \"ebsi\".");
        }
        if(config.getDidStorePath() != null)
            this.dir = new File(config.getDidStorePath());
        if(!this.dir.isDirectory())
            this.dir.mkdirs();
        if(!dir.canRead() || !dir.canWrite()){
            throw new IllegalArgumentException("Sin permisos necesarios para usar el directorio " + dir);
        }
        resolver = new EBSIDIDDocResolver(config);

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
        //System.out.println(generateDidDocument(did, (KeyHandlerEd25519.PublicKeyEd25519) publicKey));

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

    /*private void storeDID(String did, String didDoc){
        did = did.replaceFirst(":", "%3");
        did = did.replaceFirst(":", "%3");
        File file = new File(dir, did);
        if(file.exists()){
            throw new IllegalArgumentException("DID already exists");
        }
        try {
            String path = file.getAbsolutePath();
            file.createNewFile();
            PrintWriter pw = new PrintWriter(file);
            pw.print(didDoc);
            pw.close();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }*/


    public boolean registerDID(String did, String didDocument){
        RestTemplate restTemplate = new RestTemplate();
        ResponseEntity<Boolean> response =
                restTemplate.postForEntity(didRegistry + "/register?did=" + did, didDocument, Boolean.class, (Object) null);
        return response.getBody().booleanValue();
    }

    @Override
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

    @Override
    public File getDir() {
        return dir;
    }

    public Object getKeyIdFromDIDDoc(DIDDocument didDoc){
        return didDoc.getVerificationMethods().get(0).getPublicKeyJwk().get("kid");
    }

    /*
    public List<String> listDids(){
        Predicate<String> isDID = (did) -> did.matches("did%3" + getDIDMethod() + "%3*");
        List<String> list = Arrays.stream(dir.listFiles())
                .toList()
                .stream()
                .map(File::getName)
                .filter(isDID)
                .map((s) -> {s = s.replace("%3", ":"); return s; })
                .toList();
        return list;
    }

    public boolean isDID(File f){
        Predicate<String> isDID = (did) -> did.matches("did%3" + getDIDMethod() + "%3*");
        return isDID.test(f.getName());
        //return f.getName().matches("did%3" + getDIDMethod() + "%3*" );
    }

    public String getDidDoc(String did){
        did = did.replaceFirst(":", "%3");
        did = did.replaceFirst(":", "%3");
        File f = new File(dir, did);
        if(!f.exists()){
            throw new IllegalArgumentException("DID has not been created");
        }
        try {
            Scanner sc = new Scanner(f);
            StringBuilder stringBuilder = new StringBuilder();
            while(sc.hasNext()){
                stringBuilder.append(sc.nextLine());
                if(sc.hasNext())
                    stringBuilder.append("\n");
            }
            String res = stringBuilder.toString();
            DIDDocument.fromJson(res);
            return res;

        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        }
    }*/

}
