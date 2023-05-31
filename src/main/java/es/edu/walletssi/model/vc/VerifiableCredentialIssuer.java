package es.edu.walletssi.model.vc;

import com.danubetech.keyformats.crypto.ByteSigner;
import com.danubetech.keyformats.crypto.impl.Ed25519_EdDSA_PrivateKeySigner;
import com.danubetech.verifiablecredentials.CredentialSubject;
import com.danubetech.verifiablecredentials.VerifiableCredential;
import com.danubetech.verifiablecredentials.jwt.JwtVerifiableCredential;
import com.danubetech.verifiablecredentials.jwt.ToJwtConverter;
import com.nimbusds.jose.JOSEException;
import foundation.identity.did.DIDDocument;
import es.edu.walletssi.model.vc.signature.Signature;
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

public class VerifiableCredentialIssuer {

    File created;

    File owned;

    public VerifiableCredentialIssuer(String created, String owned){
        this.created = new File(created);
        this.owned = new File(owned);
        if(!this.created.isDirectory())
            this.created.mkdirs();
        if(!this.owned.isDirectory())
            this.owned.mkdirs();

        if(!this.created.canRead() || !this.created.canWrite()){
            throw new IllegalArgumentException();
        }

        if(!this.owned.canRead() || !this.owned.canWrite()){
            throw new IllegalArgumentException();
        }
    }

    public VerifiableCredential issue(Map<String, Object> claims, String didIssuer, String didHolder, Date expirationDate, boolean store){
        CredentialSubject credentialSubject = CredentialSubject.builder()
                .claims(claims)
                .id(URI.create(didHolder))
                .build();

        VerifiableCredential vc = VerifiableCredential.builder()
                .issuer(URI.create(didIssuer))
                .credentialSubject(credentialSubject)
                .expirationDate(expirationDate)
                .issuanceDate(Date.from(Instant.now()))
                .build();

        if(store)
            store(vc, created);

        return vc;
    }

    public VerifiableCredential issue(@NotNull String schema, String type, Map<String, Object> claims, String didIssuer, String didHolder, Date expirationDate, boolean store){
        CredentialSubject credentialSubject = CredentialSubject.builder()
                .claims(claims)
                .id(URI.create(didHolder))
                .build();

        VerifiableCredential vc = VerifiableCredential.builder()
                .issuer(URI.create(didIssuer))
                .type(type)
                .defaultContexts(true)
                .credentialSubject(credentialSubject)
                .expirationDate(expirationDate)
                .issuanceDate(Date.from(Instant.now()))
                .build();

        Map<String, Object> credentialSchema = new HashMap<String, Object>();
        credentialSchema.put("id", schema); credentialSchema.put("type", "JsonSchemaValidator2018");
        Map<String, Object> credential = vc.toMap();
        credential.put("credentialSchema", credentialSchema);

        vc = VerifiableCredential.fromJsonObject(credential);
        if(store)
            store(vc, created);
        return vc;
    }


    public String signJWT(VerifiableCredential vc, KeyPair keyPair){
        byte[] signData = new byte[64];
        System.arraycopy(keyPair.getPrivate().getEncoded(), 0, signData, 0, 32);
        System.arraycopy(keyPair.getPublic().getEncoded(), 0, signData, 32, 32);
        ByteSigner byteSigner = new Ed25519_EdDSA_PrivateKeySigner(signData);

        JwtVerifiableCredential jwtVerifiableCredential = ToJwtConverter.toJwtVerifiableCredential(vc);
        String jwtPayload = jwtVerifiableCredential.getPayload().toString();
        String jwtString = null;
        try {
            jwtString = jwtVerifiableCredential.sign_Ed25519_EdDSA(byteSigner);
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }
        return jwtString;
    }

    public String signVC(VerifiableCredential vc, KeyPair keyPair, String didIssuer, DIDDocument didIssuerDocument){
        return Signature.signJsonLD(vc, keyPair, didIssuer, didIssuerDocument);
    }


    private void store(VerifiableCredential vc, File dir){

        File file = new File(dir, "VerifiableCredential_" + Instant.now().toString().replace(":","%3"));
        if(file.exists()){
            throw new IllegalArgumentException("Credential can´t be stored");
        }
        try {
            file.createNewFile();
            PrintWriter pw = new PrintWriter(file);
            pw.print(vc.toJson(true));
            pw.close();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public void storeVc(String vc){
        store(VerifiableCredential.fromJson(vc), owned);
    }

    public String getCreatedVC(String vcName){
        return getVC(vcName, created);
    }

    public String getOwnedVC(String vcName){
        return getVC(vcName, owned);
    }

    private String getVC(String vcName, File dir){
        File f = new File(dir, vcName);
        if(!f.exists()){
            throw new IllegalArgumentException("Credential does not exist");
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

    public List<String> listOwnedVC(String schema){
        if(schema == null || schema.isEmpty()){
            return listVC(owned);
        }
        return listVCBySchema(schema, owned);
    }

    public List<String> listCreatedVC(String schema){
        if(schema == null || schema.isEmpty()){
            return listVC(created);
        }
        return listVCBySchema(schema, created);
    }


    private List<String> listVC(File dir){
        Predicate<String> isVC = (vcName) -> vcName.matches("VerifiableCredential_" + ".*?");
        List<String> list = Arrays.stream(dir.listFiles())
                .toList()
                .stream()
                .map(File::getName)
                .filter(isVC)
                .toList();
        return list;
    }

    public List<String> listVCBySchema(String schema, File dir){
        Predicate<String> isVC = (vcName) -> vcName.matches("VerifiableCredential_" + ".*?");
        Predicate<File> followsSchema = (file) -> isVC.test(file.getName()) && VerifiableCredentialVerifier.validateJSONSchema(getVC(file.getName(), dir), schema);

        List<String> list = Arrays.stream(dir.listFiles())
                .toList()
                .stream()
                .filter(followsSchema)
                .map(File::getName)
                .toList();
        return list;
    }

}
