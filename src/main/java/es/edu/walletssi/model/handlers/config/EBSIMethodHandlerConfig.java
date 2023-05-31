package es.edu.walletssi.model.handlers.config;

import org.jetbrains.annotations.NotNull;

public class EBSIMethodHandlerConfig implements DidMethodHandlerConfig{
    private String didStorePath = "data/did/created";
    private String ebsiMethod = "ebsi";

    private String didRegistry = "http://localhost:8080";

    public EBSIMethodHandlerConfig(String didStorePath, String ebsiMethod, String didRegistry){
        if(didStorePath != null)
            this.didStorePath = didStorePath;
        if(ebsiMethod != null)
            this.ebsiMethod = ebsiMethod;
        if(didRegistry != null)
            this.didRegistry = didRegistry;
    }

    public EBSIMethodHandlerConfig(){}

    public String getDidStorePath() {
        return didStorePath;
    }

    public String getEbsiMethod() {
        return ebsiMethod;
    }

    public String getDidRegistry() {
        return didRegistry;
    }

    public void setDidStorePath(@NotNull String didStorePath) {
        this.didStorePath = didStorePath;
    }

    public void setEbsiMethod(@NotNull String ebsiMethod) {
        this.ebsiMethod = ebsiMethod;
    }

    public void setDidRegistry(@NotNull String didRegistry) {
        this.didRegistry = didRegistry;
    }
}
