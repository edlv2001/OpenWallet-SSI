package es.edu.walletssi.model.handlers;


import es.edu.walletssi.key.utils.KeyUtils;
import es.edu.walletssi.model.exception.UnsupportedKeyAlgorithm;
import foundation.identity.did.DIDDocument;
import foundation.identity.did.VerificationMethod;
import io.ipfs.multibase.Multibase;
import org.didcommx.didcomm.diddoc.DIDDocResolver;
import es.edu.walletssi.model.handlers.config.DefaultMethodHandlerConfig;
import es.edu.walletssi.model.resolver.KeyDIDDocResolver;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.URI;
import java.nio.ByteBuffer;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.List;
import java.util.Scanner;
import java.util.function.Predicate;

public class KeyMethodHandler implements DidMethodHandler {
    private File dir;

    byte[] multicodecEd25519Bytes = ByteBuffer.allocate(2).putShort((short) 0xED01).array();

    byte[] multicodecRSABytes =  ByteBuffer.allocate(2).putShort((short) 0x1205).array();

    byte[] multicodecBytes = ByteBuffer.allocate(2).putShort((short) 0xED01).array();

    byte[] multicodecExampleBytes = ByteBuffer.allocate(2).putShort((short) 0xED01).array();

    public KeyMethodHandler(DefaultMethodHandlerConfig config){
        this.dir = new File(config.getDidStorePath());
        if(!this.dir.isDirectory())
            this.dir.mkdirs();
        if(!dir.canRead() || !dir.canWrite()){
            throw new IllegalArgumentException("Sin permisos necesarios para usar el directorio " + dir);
        }
    }
    public KeyMethodHandler(DefaultMethodHandlerConfig config, boolean aux){
        this.dir = new File(config.getDidStorePath());
    }

    public String genDID(PublicKey publicKey){
        byte[] publicKeyBytes = publicKey.getEncoded();
        byte[] multicodec = getMulticodecBytes(publicKey.getAlgorithm());

        byte[] publicKeyWithMulticodec = new byte[multicodec.length + publicKeyBytes.length];
        System.arraycopy(multicodec, 0, publicKeyWithMulticodec, 0, multicodec.length);
        System.arraycopy(publicKeyBytes, 0, publicKeyWithMulticodec, multicodec.length, publicKeyBytes.length);

        String multibasePublicKey = Multibase.encode(Multibase.Base.Base58BTC, publicKeyWithMulticodec);

        String did = "did:key:" + multibasePublicKey;
        this.storeDID(did, generateDidDocument(did, publicKey));
        return did;
    }

    public String generateDidDocument(String did, PublicKey publicKey) {
        String identifier = did.substring(8);
        String auth = did + "#" + identifier;
        String keyType = getKeyType(identifier);

        VerificationMethod verificationMethod = VerificationMethod.builder()
                .id(URI.create(auth))
                .type(keyType)
                .publicKeyJwk(KeyUtils.publicKeyToJWK(publicKey).toJSONObject())
                .build();
        VerificationMethod assertion = VerificationMethod.builder().id(URI.create(auth)).build();
        String res = DIDDocument.builder()
                .id(URI.create(did))
                .verificationMethod(verificationMethod)
                .assertionMethodVerificationMethod(assertion)
                .authenticationVerificationMethod(assertion)
                .build().toJson(true);

        return res;
    }


    private String getKeyType(String identifier){
        switch (identifier.substring(0,4)){
            case "z6Mk":
                return "Ed25519VerificationType2020";
            case "z4MX":
            case "zBbU":
                return "RSASignature2018";
        }
        throw new UnsupportedKeyAlgorithm("Unsupported Key Type");
    }

    private byte[] getMulticodecBytes(String algorithm){
        switch (algorithm){
            case "RSA": return multicodecRSABytes;
            case "EC": return multicodecEd25519Bytes;
            default: return null;
        }
    }

    @Override
    public String getDIDMethod() {
        return "key";
    }

    @Override
    public DIDDocResolver getResolver() {
        return new KeyDIDDocResolver();
    }

    @Override
    public File getDir() {
        return dir;
    }

    public Class<?> getConfigClass(){ return DefaultMethodHandlerConfig.class; }

    @Override
    public String getSchemaRegistry() {
        return null;
    }

    @Override
    public String getDIDRegistry() {
        return null;
    }

    @Override
    public String getDidDocFromFile(String did){
        did = did.replaceFirst(":", "%3");
        did = did.replaceFirst(":", "%3");
        File f = new File(getDir(), did);
        for(File file : getDir().listFiles()){
            if(file.getName().startsWith(did) || did.startsWith(file.getName())){
                f = file;
            }
        }
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
            return null;
        }
    }

    private String getFullDid(String didIncomplete){
        for(File file : getDir().listFiles()){
            if(file.getName().startsWith(didIncomplete) || didIncomplete.startsWith(file.getName())){
                Scanner sc = null;
                try {
                    sc = new Scanner(file);
                } catch (FileNotFoundException e) {
                    throw new RuntimeException(e);
                }
                StringBuilder stringBuilder = new StringBuilder();
                while(sc.hasNext()){
                    stringBuilder.append(sc.nextLine());
                    if(sc.hasNext())
                        stringBuilder.append("\n");
                }
                String res = stringBuilder.toString();

                return DIDDocument.fromJson(res).getId().toString();
            }
        }
        return null;
    }

    @Override
    public List<String> listDids(){
        Predicate<String> isDID = (did) -> did.matches("did%3" + getDIDMethod() + "%3.*?");
        List<String> list = Arrays.stream(getDir().listFiles())
                .toList()
                .stream()
                .map(File::getName)
                .filter(isDID)
                .map((String s) -> {s = getFullDid(s); return s; })
                .toList();
        return list;
    }

    public void storeDID(String did, String didDoc){
        did = did.replaceFirst(":", "%3");
        did = did.replaceFirst(":", "%3");
        File file = new File(getDir(), did.substring(0,200));
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
