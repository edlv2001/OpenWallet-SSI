package es.edu.walletssi.model;


import es.edu.walletssi.model.exception.UnsupportedDidMethod;
import es.edu.walletssi.model.handlers.DidMethodHandler;
import es.edu.walletssi.model.handlers.KeyMethodHandler;
import es.edu.walletssi.model.handlers.config.DefaultMethodHandlerConfig;
import es.edu.walletssi.model.handlers.config.DidMethodHandlerConfig;
import es.edu.walletssi.model.handlers.config.EBSIMethodHandlerConfig;
import es.edu.walletssi.model.resolver.KeyDIDDocResolver;
import org.didcommx.didcomm.diddoc.DIDDocResolver;
import es.edu.walletssi.model.handlers.EBSIMethodHandler;
import es.edu.walletssi.model.resolver.EBSIDIDDocResolver;

public enum DidMethod {
    EBSI,
    KEY;

    public static DidMethodHandler getHandlerInit(DidMethod didMethod, DidMethodHandlerConfig config) throws UnsupportedDidMethod {
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

    public static DidMethodHandler getHandler(DidMethod didMethod, DidMethodHandlerConfig config) throws UnsupportedDidMethod {
        switch(didMethod){
            case KEY -> {
                if(config instanceof DefaultMethodHandlerConfig)
                    return new KeyMethodHandler((DefaultMethodHandlerConfig) config, false);
                return new KeyMethodHandler(new DefaultMethodHandlerConfig(), false);
            }
            case EBSI -> {
                if(config instanceof EBSIMethodHandlerConfig)
                    return new EBSIMethodHandler((EBSIMethodHandlerConfig) config, false);
                return new EBSIMethodHandler(new EBSIMethodHandlerConfig(), false);
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

}
