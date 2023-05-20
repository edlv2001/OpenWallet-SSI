package org.example.walletssi.model.handlers.config;

import org.jetbrains.annotations.NotNull;

public class DefaultMethodHandlerConfig implements DidMethodHandlerConfig{
    private String didStorePath;

    public DefaultMethodHandlerConfig(@NotNull String didStorePath){
        this.didStorePath = didStorePath;
    }

    public String getDidStorePath() {
        return didStorePath;
    }

    public void setDidStorePath(@NotNull String didStorePath) {
        this.didStorePath = didStorePath;
    }
}
