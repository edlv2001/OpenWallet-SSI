package org.example.walletssi.key;

import io.github.novacrypto.bip39.MnemonicGenerator;
import io.github.novacrypto.bip39.Words;
import io.github.novacrypto.bip39.wordlists.English;

import java.security.KeyPair;
import java.security.SecureRandom;

public interface KeyHandler {

    public KeyPair generateKeys(byte[] seed);

    public void storeKey(KeyPair keyPair, String alias, String password);

    default String generateMnemonic() {
        StringBuilder sb = new StringBuilder();
        byte[] entropy = new byte[Words.FIFTEEN.byteLength()];
        new SecureRandom().nextBytes(entropy);
        new MnemonicGenerator(English.INSTANCE)
                .createMnemonic(entropy, sb::append);
        return sb.toString();
    }

    public void destroyKey(String alias, String password);

    public byte[] generateSeed(String mnemonic, String passphrase);

    public KeyPair obtainKey(String alias, String password);


}
