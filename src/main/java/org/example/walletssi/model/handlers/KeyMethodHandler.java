package org.example.walletssi.model.handlers;

import foundation.identity.did.DID;
import foundation.identity.did.DIDDocument;
import io.ipfs.multibase.Base58;
import io.ipfs.multibase.Multibase;
import org.example.walletssi.model.DIDResolver;
import org.example.walletssi.model.DidMethodHandler;
import uniresolver.ResolutionException;
import uniresolver.client.ClientUniResolver;
import uniresolver.driver.AbstractDriver;
import uniresolver.driver.Driver;
import uniresolver.local.LocalUniResolver;
import uniresolver.result.ResolveDataModelResult;

import java.nio.ByteBuffer;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class KeyMethodHandler implements DidMethodHandler {

    public String genDid(PublicKey publicKey){
        byte[] publicKeyBytes = publicKey.getEncoded();
        byte[] multicodecEd25519Bytes = ByteBuffer.allocate(2).putShort((short) 0xED01).array();
        byte[] publicKeyWithMulticodec = new byte[multicodecEd25519Bytes.length + publicKeyBytes.length];
        System.arraycopy(multicodecEd25519Bytes, 0, publicKeyWithMulticodec, 0, multicodecEd25519Bytes.length);
        System.arraycopy(publicKeyBytes, 0, publicKeyWithMulticodec, multicodecEd25519Bytes.length, publicKeyBytes.length);

        String multibasePublicKey = Multibase.encode(Multibase.Base.Base58BTC, publicKeyWithMulticodec);
        return "did:key:" + multibasePublicKey;

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
}
