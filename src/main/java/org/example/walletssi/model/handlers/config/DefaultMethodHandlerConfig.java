package org.example.walletssi.model.handlers.config;

import org.example.walletssi.model.handlers.DidMethodHandler;
import org.jetbrains.annotations.NotNull;

public class DefaultMethodHandlerConfig implements DidMethodHandlerConfig{

    private String didStorePath = "data/did/created";

    public DefaultMethodHandlerConfig(String didStorePath){
        if(didStorePath != null)
            this.didStorePath = didStorePath;
    }

    public DefaultMethodHandlerConfig(){}

    public String getDidStorePath() {
        return didStorePath;
    }

    public void setDidStorePath(@NotNull String didStorePath) {
        this.didStorePath = didStorePath;
    }
}
