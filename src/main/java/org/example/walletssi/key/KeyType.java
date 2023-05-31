package org.example.walletssi.key;

public enum KeyType {
    RSA,
    ED25519;
    public static KeyHandler[] keyHandlers(String keypath){
        KeyHandler[] keyHandlers = new KeyHandler[KeyType.values().length];
        keyHandlers[RSA.ordinal()] = new KeyHandlerRSA(keypath);
        keyHandlers[ED25519.ordinal()] = new KeyHandlerEd25519(keypath);

        return keyHandlers;
    }

}
