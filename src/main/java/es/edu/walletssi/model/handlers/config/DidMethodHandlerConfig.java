package es.edu.walletssi.model.handlers.config;

public interface DidMethodHandlerConfig {
    static DidMethodHandlerConfig defaultConfig(){
        return new DefaultMethodHandlerConfig();
    }
}
