package org.example.walletssi.model.didUtils;

import org.example.walletssi.model.DidMethod;
import org.example.walletssi.model.exception.UnsupportedDidMethod;

public class DIDParser {
    public static DidMethod parseDID(String did) throws IllegalArgumentException, UnsupportedDidMethod {
        String[] divided;
        if((divided = did.split(":")).length != 3 || !divided[0].equals("did")){
            throw new IllegalArgumentException("");
        }
        try {
            DidMethod result = DidMethod.valueOf(divided[1].toUpperCase());
            return result;
        } catch (IllegalArgumentException e){
            throw new UnsupportedDidMethod("");
        }
    }

    public static boolean isValid(String did, DidMethod didMethod){
        return parseDID(did).equals(didMethod);
    }
}
