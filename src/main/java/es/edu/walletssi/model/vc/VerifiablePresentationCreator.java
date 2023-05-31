package es.edu.walletssi.model.vc;

import com.danubetech.verifiablecredentials.VerifiableCredential;
import com.danubetech.verifiablecredentials.VerifiablePresentation;
import es.edu.walletssi.model.vc.signature.Signature;
import foundation.identity.did.DIDDocument;
import org.jetbrains.annotations.NotNull;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.URI;
import java.security.KeyPair;
import java.time.Instant;
import java.util.*;
import java.util.function.Predicate;

public class VerifiablePresentationCreator {

    private File created;

    public VerifiablePresentationCreator(String path){
        this.created = new File(path);
        if(!this.created.isDirectory())
            this.created.mkdirs();
        if(!created.canRead() || !created.canWrite()){
            throw new IllegalArgumentException();
        }

    }

    public VerifiablePresentation issueVP(String vc, String did, boolean store){
        VerifiableCredentialVerifier verifier = new VerifiableCredentialVerifier();

        VerifiablePresentation vp = VerifiablePresentation.builder()
                .verifiableCredential(VerifiableCredential.fromJson(vc))
                .defaultContexts(true)
                .defaultTypes(true)
                .holder(URI.create(did))
                .build();

        if(store)
            store(vp);
        return vp;
    }

    public VerifiablePresentation issueVP(@NotNull String schema, String type, String vc, String did, boolean store){
        VerifiableCredential credential = VerifiableCredential.fromJson(vc);
        VerifiablePresentation vp = VerifiablePresentation.builder()
                .verifiableCredential(credential)
                .defaultContexts(true)
                .defaultTypes(true)
                .types(credential.getTypes().subList(0,credential.getTypes().size()))
                .holder(URI.create(did))
                .type(type)
                .build();

        Map<String, Object> credentialSchema = new HashMap<>();
        credentialSchema.put("id", schema); credentialSchema.put("type", "JsonSchemaValidator2018");
        Map<String, Object> presentation = vp.toMap();
        presentation.put("credentialSchema", credentialSchema);

        vp = VerifiablePresentation.fromJsonObject(presentation);
        if(store)
            store(vp);
        return vp;
    }

    public String signVP(VerifiablePresentation vp, KeyPair keyPair, String did, DIDDocument didDocument){
        return Signature.signJsonLD(vp, keyPair, did, didDocument);
    }


    private void store(VerifiablePresentation vp){
        File file = new File(created, "VerifiablePresentation_" + Instant.now().toString().replace(":","%3"));
        if(file.exists()){
            throw new IllegalArgumentException("Presentation can´t be stored");
        }
        try {
            file.createNewFile();
            PrintWriter pw = new PrintWriter(file);
            pw.print(vp.toJson(true));
            pw.close();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }


    public String getVP(String vpName){
        File f = new File(created, vpName);
        if(!f.exists()){
            throw new IllegalArgumentException("Presentation does not exist");
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
            return null;
        }
    }

    public List<String> listVP(String schema){
        if(schema == null || schema.isEmpty())
            return listAllVP();
        return listVP(schema);
    }

    public List<String> listAllVP(){
        Predicate<String> isVP = (vcName) -> vcName.matches("VerifiablePresentation_" + ".*?");
        List<String> list = Arrays.stream(created.listFiles())
                .toList()
                .stream()
                .map(File::getName)
                .filter(isVP)
                .toList();
        return list;
    }

    public List<String> listVPBySchema(String schema){
        Predicate<String> isVC = (vcName) -> vcName.matches("VerifiablePresentation_" + ".*?");
        Predicate<File> followsSchema = (file) -> isVC.test(file.getName()) && VerifiableCredentialVerifier.validateJSONSchema(getVP(file.getName()), schema);
        List<String> list = Arrays.stream(created.listFiles())
                .toList()
                .stream()
                .filter(followsSchema)
                .map(File::getName)
                .toList();
        return list;
    }



}
