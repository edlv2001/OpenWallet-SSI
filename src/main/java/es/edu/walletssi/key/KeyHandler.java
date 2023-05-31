package es.edu.walletssi.key;

import io.github.novacrypto.bip39.MnemonicGenerator;
import io.github.novacrypto.bip39.Words;
import io.github.novacrypto.bip39.wordlists.English;
import org.didcommx.didcomm.common.VerificationMethodType;

import java.io.File;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.ArrayList;

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

    default ArrayList<String> listAlias(){
        File[] fileList = getDir().listFiles();
        ArrayList<String> list = new ArrayList<>();
        for(File file: fileList){
            if(file.isDirectory() && validDir(file.getPath())){
                list.add(file.getName().split(" - ", 2)[1]);
            }
        }
        return list;
    }

    public File getDir();

    public boolean validDir(String path);

    public void destroyKey(String alias, String password);

    public byte[] generateSeed(String mnemonic, String passphrase);

    public KeyPair obtainKey(String alias, String password);

    public VerificationMethodType getKeyTyp();

    public boolean recoverKey(KeyPair keyPair, String alias, String password);












}
