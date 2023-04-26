package org.example.walletssi.model;


import org.checkerframework.checker.units.qual.K;
import org.example.walletssi.model.exception.UnsupportedDidMethod;
import org.example.walletssi.model.handlers.EBSIMethodHandler;
import org.example.walletssi.model.handlers.KeyMethodHandler;

public enum DidMethod {
    EBSI,
    KEY,
    ETHR;

    public DidMethodHandler getResolver(DidMethod didMethod) throws UnsupportedDidMethod {
        switch(didMethod){
            case KEY -> {
                return new KeyMethodHandler();
            }
            case EBSI -> {
                return new EBSIMethodHandler();
            }
            case ETHR -> {
                return new KeyMethodHandler();
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
