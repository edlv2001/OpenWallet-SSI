package org.example.walletssi.model.handlers;

import foundation.identity.did.DIDDocument;
import foundation.identity.did.VerificationMethod;
import io.ipfs.multibase.Multibase;
import org.didcommx.didcomm.diddoc.DIDDocResolver;
import org.example.walletssi.key.utils.KeyUtils;
import org.example.walletssi.model.exception.UnsupportedKeyAlgorithm;
import org.example.walletssi.model.handlers.config.DefaultMethodHandlerConfig;
import org.example.walletssi.model.handlers.config.DidMethodHandlerConfig;
import org.example.walletssi.model.resolver.KeyDIDDocResolver;
import uniresolver.ResolutionException;
import uniresolver.client.ClientUniResolver;
import uniresolver.result.ResolveDataModelResult;

import java.io.File;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.PublicKey;
import java.util.List;

public class KeyMethodHandler implements DidMethodHandler {
    private File dir;

    byte[] multicodecEd25519Bytes = ByteBuffer.allocate(2).putShort((short) 0xED01).array();

    byte[] multicodecRSABytes =  ByteBuffer.allocate(2).putShort((short) 0x1205).array();

    byte[] multicodecBytes = ByteBuffer.allocate(2).putShort((short) 0xED01).array();

    byte[] multicodecExampleBytes = ByteBuffer.allocate(2).putShort((short) 0xED01).array();


    public KeyMethodHandler(){
        this("data/did/created");
    }
    public KeyMethodHandler(String path){
        this.dir = new File(path);
    }

    public KeyMethodHandler(DefaultMethodHandlerConfig config){
        this.dir = new File(config.getDidStorePath());
        if(!this.dir.isDirectory())
            this.dir.mkdirs();
        if(!dir.canRead() || !dir.canWrite()){
            throw new IllegalArgumentException("Sin permisos necesarios para usar el directorio " + dir);
        }
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

        //return "did:key:" + Base58.encode(publicKey.getEncoded());
    }

    public String generateDidDocument(String did, PublicKey publicKey) {
        //uniresolver.local.LocalUniResolver l = new LocalUniResolver();
        /*uniresolver.driver.AbstractDriver abstractDriver = new AbstractDriver() {
            @Override
            public ResolveDataModelResult resolve(DID did, Map<String, Object> resolutionOptions) throws ResolutionException {
                return super.resolve(did, resolutionOptions);
            }
        };

        List<Driver> drivers = new ArrayList<>();
        drivers.add(abstractDriver);
        l.setDrivers(drivers);
*/

        /*
        ClientUniResolver uniResolver = new ClientUniResolver();
        uniResolver.setResolveUri("https://dev.uniresolver.io/1.0/identifiers");
        ResolveDataModelResult result = null;
        try {
            result = uniResolver.resolve(did);
        } catch (ResolutionException e) {
            throw new RuntimeException(e);
        }
        DIDDocument didDocument = result.getDidDocument();

         */
        //String res = (new KeyDIDDocResolver()).resolve(did).get().toString();
        //System.out.println(res);
        System.out.println(did);
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


        System.out.println(res);
        return res;

        //return didDocument.toJson(true);
    }


    private String getKeyType(String identifier){
        switch (identifier.substring(0,4)){
            case "z6Mk":
                return "Ed25519VerificationType2020";
            case "z4MX":
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
    public DIDDocument resolveDID(String did) {
        ClientUniResolver uniResolver = new ClientUniResolver();
        uniResolver.setResolveUri("https://dev.uniresolver.io/1.0/identifiers");
        ResolveDataModelResult result = null;
        try {
            result = uniResolver.resolve(did);
        } catch (ResolutionException e) {
            throw new RuntimeException(e);
        }
        return result.getDidDocument();
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
}
