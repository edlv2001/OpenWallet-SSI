package org.example.walletssi.model;


import org.didcommx.didcomm.diddoc.DIDDocResolver;
import org.example.walletssi.model.exception.UnsupportedDidMethod;
import org.example.walletssi.model.handlers.DidMethodHandler;
import org.example.walletssi.model.handlers.EBSIMethodHandler;
import org.example.walletssi.model.handlers.KeyMethodHandler;
import org.example.walletssi.model.handlers.config.DefaultMethodHandlerConfig;
import org.example.walletssi.model.handlers.config.DidMethodHandlerConfig;
import org.example.walletssi.model.handlers.config.EBSIMethodHandlerConfig;
import org.example.walletssi.model.resolver.EBSIDIDDocResolver;
import org.example.walletssi.model.resolver.KeyDIDDocResolver;

public enum DidMethod {
    EBSI,
    KEY;

    public static DidMethodHandler getHandler(DidMethod didMethod, DidMethodHandlerConfig config) throws UnsupportedDidMethod {
        switch(didMethod){
            case KEY -> {
                if(config instanceof DefaultMethodHandlerConfig)
                    return new KeyMethodHandler((DefaultMethodHandlerConfig) config);
                return new KeyMethodHandler(new DefaultMethodHandlerConfig());
            }
            case EBSI -> {
                if(config instanceof EBSIMethodHandlerConfig)
                    return new EBSIMethodHandler((EBSIMethodHandlerConfig) config);
                return new EBSIMethodHandler(new EBSIMethodHandlerConfig());
            }

        }
        throw new UnsupportedDidMethod("Unsupported Did Method " + didMethod);
    }

    public static DIDDocResolver getResolver(DidMethod didMethod, DidMethodHandlerConfig config) throws UnsupportedDidMethod {
        switch(didMethod){
            case KEY -> {
                return new KeyDIDDocResolver();
            }
            case EBSI -> {
                if(config instanceof EBSIMethodHandlerConfig)
                    return new EBSIDIDDocResolver((EBSIMethodHandlerConfig) config);
                return new EBSIDIDDocResolver(new EBSIMethodHandlerConfig());
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
