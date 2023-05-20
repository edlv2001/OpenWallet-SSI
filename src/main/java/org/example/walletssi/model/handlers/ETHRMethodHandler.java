package org.example.walletssi.model.handlers;

import foundation.identity.did.DIDDocument;
import org.didcommx.didcomm.diddoc.DIDDocResolver;
import org.example.walletssi.model.handlers.config.DefaultMethodHandlerConfig;

import java.io.File;
import java.security.PublicKey;

public class ETHRMethodHandler implements DidMethodHandler {

    public ETHRMethodHandler(DefaultMethodHandlerConfig config){
        this.dir = new File(config.getDidStorePath());
        if(!dir.isDirectory() || !dir.canRead() || !dir.canWrite()){
            throw new IllegalArgumentException();
        }
    }

    private File dir;
    @Override
    public String genDID(PublicKey publicKey) {
        return null;
    }

    @Override
    public DIDDocument resolveDID(String did) {
        return null;
    }

    @Override
    public String getDIDMethod() {
        return null;
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
