package org.example.walletssi.model;


import org.didcommx.didcomm.diddoc.DIDDocResolver;
import org.example.walletssi.model.exception.UnsupportedDidMethod;
import org.example.walletssi.model.handlers.DidMethodHandler;
import org.example.walletssi.model.handlers.EBSIMethodHandler;
import org.example.walletssi.model.handlers.ETHRMethodHandler;
import org.example.walletssi.model.handlers.KeyMethodHandler;
import org.example.walletssi.model.handlers.config.DefaultMethodHandlerConfig;
import org.example.walletssi.model.handlers.config.DidMethodHandlerConfig;
import org.example.walletssi.model.handlers.config.EBSIMethodHandlerConfig;
import org.example.walletssi.model.resolver.EBSIDIDDocResolver;

public enum DidMethod {
    EBSI,
    KEY,
    ETHR;

    public static DidMethodHandler getHandler(DidMethod didMethod, DidMethodHandlerConfig config) throws UnsupportedDidMethod {
        switch(didMethod){
            case KEY -> {
                return new KeyMethodHandler((DefaultMethodHandlerConfig) config);
            }
            case EBSI -> {
                return new EBSIMethodHandler((EBSIMethodHandlerConfig) config);
            }
            case ETHR -> {
                return new ETHRMethodHandler((DefaultMethodHandlerConfig) config);
            }
        }
        throw new UnsupportedDidMethod("Unsupported Did Method " + didMethod);
    }

    public static DIDDocResolver getResolver(DidMethod didMethod, DidMethodHandlerConfig config) throws UnsupportedDidMethod {
        switch(didMethod){
            case KEY -> {
                return null;
            }
            case EBSI -> {
                return new EBSIDIDDocResolver((EBSIMethodHandlerConfig) config);
            }
            case ETHR -> {
                return null;
            }
        }
        throw new UnsupportedDidMethod("Unsupported Did Method " + didMethod);
    }

    public id.walt.model.DidMethod map(DidMethod didMethod){
        switch (didMethod){
            case EBSI -> {
                return id.walt.model.DidMethod.ebsi;
            }
            case KEY -> {
                return id.walt.model.DidMethod.key;
            }
        }
        return null;
    }

}
