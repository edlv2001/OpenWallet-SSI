package org.example.walletssi.model.handlers;

import foundation.identity.did.DIDDocument;
import io.ipfs.multibase.Multibase;
import org.didcommx.didcomm.diddoc.DIDDocResolver;
import org.example.walletssi.model.handlers.config.DefaultMethodHandlerConfig;
import org.example.walletssi.model.handlers.config.DidMethodHandlerConfig;
import uniresolver.ResolutionException;
import uniresolver.client.ClientUniResolver;
import uniresolver.result.ResolveDataModelResult;

import java.io.File;
import java.nio.ByteBuffer;
import java.security.PublicKey;
import java.util.List;

public class KeyMethodHandler implements DidMethodHandler {
    private File dir;

    byte[] multicodecEd25519Bytes = ByteBuffer.allocate(2).putShort((short) 0xED01).array();

    byte[] multicodecRSABytes = ByteBuffer.allocate(2).putShort((short) 0xED01).array();

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
        if(!dir.isDirectory() || !dir.canRead() || !dir.canWrite()){
            throw new IllegalArgumentException();
        }
    }

    public String genDID(PublicKey publicKey){
        byte[] publicKeyBytes = publicKey.getEncoded();
        byte[] multicodecEd25519Bytes = ByteBuffer.allocate(2).putShort((short) 0xED01).array();
        byte[] publicKeyWithMulticodec = new byte[multicodecEd25519Bytes.length + publicKeyBytes.length];
        System.arraycopy(multicodecEd25519Bytes, 0, publicKeyWithMulticodec, 0, multicodecEd25519Bytes.length);
        System.arraycopy(publicKeyBytes, 0, publicKeyWithMulticodec, multicodecEd25519Bytes.length, publicKeyBytes.length);

        String multibasePublicKey = Multibase.encode(Multibase.Base.Base58BTC, publicKeyWithMulticodec);


        String did = "did:key:" + multibasePublicKey;
        System.out.println(did);
        this.storeDID(did, generateDidDocument(did));
        return did;

        //return "did:key:" + Base58.encode(publicKey.getEncoded());
    }

    public String generateDidDocument(String did) {
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
        ClientUniResolver uniResolver = new ClientUniResolver();
        uniResolver.setResolveUri("https://dev.uniresolver.io/1.0/identifiers");
        ResolveDataModelResult result = null;
        try {
            result = uniResolver.resolve(did);
        } catch (ResolutionException e) {
            throw new RuntimeException(e);
        }
        DIDDocument didDocument = result.getDidDocument();

        return didDocument.toJson(true);
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
        return null;
    }

    @Override
    public File getDir() {
        return dir;
    }

    public Class<?> getConfigClass(){ return DefaultMethodHandlerConfig.class; }

}
