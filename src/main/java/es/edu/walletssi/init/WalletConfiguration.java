package es.edu.walletssi.init;

import es.edu.walletssi.model.DidMethod;
import es.edu.walletssi.model.handlers.config.DidMethodHandlerConfig;
import org.jetbrains.annotations.NotNull;

public class WalletConfiguration {
    private DidMethod didMethod;
    private String keyStorePath = "data/key";
    private String didStorePath = "data/did/created";
    private String vcOwnedPath = "data/vc/owned";
    private String vcCreatedPath = "data/vc/created";
    private String vpStorePath = "data/vc/presented";
    private DidMethodHandlerConfig didMethodHandlerConfig;

    public WalletConfiguration(@NotNull DidMethod didMethod, @NotNull DidMethodHandlerConfig didMethodHandlerConfig, String keyStorePath, String vcOwnedPath, String vcCreatedPath, String vpStorePath){
        this.didMethod = didMethod;
        this.didMethodHandlerConfig = didMethodHandlerConfig;
        if(keyStorePath != null)
            this.keyStorePath = keyStorePath;

        if(didStorePath != null)
            this.didStorePath = didStorePath;

        if(vcOwnedPath != null)
            this.vcOwnedPath = vcOwnedPath;

        if(vcCreatedPath != null)
            this.vcCreatedPath = vcCreatedPath;

        if(vpStorePath != null)
            this.vpStorePath = vpStorePath;
    }

    public void setDidMethod(@NotNull DidMethod didMethod) {
        this.didMethod = didMethod;
    }

    public void setKeyStorePath(@NotNull String keyStorePath) {
        this.keyStorePath = keyStorePath;
    }

    public void setDidStorePath(@NotNull String didStorePath) {
        this.didStorePath = didStorePath;
    }

    public void setVcOwnedPath(@NotNull String vcOwnedPath) {
        this.vcOwnedPath = vcOwnedPath;
    }

    public void setVcCreatedPath(@NotNull String vcCreatedPath) {
        this.vcCreatedPath = vcCreatedPath;
    }

    public void setVpStorePath(@NotNull String vpStorePath) {
        this.vpStorePath = vpStorePath;
    }

    public void setDidMethodHandlerConfig(DidMethodHandlerConfig didMethodHandlerConfig) {
        this.didMethodHandlerConfig = didMethodHandlerConfig;
    }

    public String getDidStorePath() {
        return didStorePath;
    }

    public DidMethod getDidMethod() {
        return didMethod;
    }

    public String getKeyStorePath() {
        return keyStorePath;
    }

    public String getVcCreatedPath() {
        return vcCreatedPath;
    }

    public String getVcOwnedPath() {
        return vcOwnedPath;
    }

    public String getVpStorePath() {
        return vpStorePath;
    }

    public DidMethodHandlerConfig getDidMethodHandlerConfig() {
        return didMethodHandlerConfig;
    }
}
