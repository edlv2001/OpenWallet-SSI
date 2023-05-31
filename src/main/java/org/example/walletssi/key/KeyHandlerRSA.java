package org.example.walletssi.key;

import com.google.crypto.tink.subtle.Hex;
import io.github.novacrypto.bip39.JavaxPBKDF2WithHmacSHA512;
import io.github.novacrypto.bip39.SeedCalculator;
import org.bouncycastle.util.test.FixedSecureRandom;
import org.didcommx.didcomm.common.VerificationMethodType;
import org.example.walletssi.key.exception.IncorrectPasswordException;
import org.example.walletssi.key.utils.KeyUtils;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;

import java.util.*;

public class KeyHandlerRSA implements KeyHandler{

    private final static String[] fileNames = {"aliases", "enc-privkey", "enc-pubkey", "meta"};
    private File dir;

    public KeyHandlerRSA(String path){
        this.dir = new File(path);
        if(!this.dir.isDirectory())
            this.dir.mkdirs();
        if(!dir.canRead() || !dir.canWrite()){
            throw new IllegalArgumentException("Sin permisos necesarios para usar el directorio " + dir);
        }
    }

    public KeyPair generateKeys(byte[] seed) {
        try {
            SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG", "SUN");
            secureRandom.setSeed(seed);
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048, secureRandom);
            KeyPair pair = keyPairGenerator.generateKeyPair();
            return pair;
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    @Override
    public void storeKey(KeyPair keyPair, String alias, String password) {
        String keyPath = Hex.encode(KeyUtils.hashSHA256(keyPair.getPublic().getEncoded())) + " - " + alias;
        File f = new File(dir, keyPath);

        File previous = findKeyDir(alias);
        if(previous != null && !previous.getName().equals(keyPath))
            throw new RuntimeException("Alias already exists for another key");

        createDir(keyPath, keyPair, password, false);
    }

    public boolean recoverKey(KeyPair keyPair, String alias, String password) {
        String keyPath = Hex.encode(KeyUtils.hashSHA256(keyPair.getPublic().getEncoded())) + " - " + alias;
        File f = new File(dir, keyPath);
        if(!f.exists()) return false;
        createDir(keyPath, keyPair, password, true);
        return true;
    }

    public KeyPair obtainKey(String alias, String password) {
        File[] fileList = dir.listFiles();
        for(File file: fileList){
            if(file.getName().endsWith(alias) && validDir(file.getPath())){
                try {
                    byte[] encryptedPublicKey = getEncryptedKey(file.getPath() + "\\enc-pubkey", "public");
                    byte[] encryptedPrivateKey = getEncryptedKey(file.getPath() + "\\enc-privkey", "private");

                    byte[] decryptedPublicKeyBytes = desencriptarClavePrivada(password.toCharArray(), encryptedPublicKey);
                    byte[] decryptedPrivateKeyBytes = desencriptarClavePrivada(password.toCharArray(), encryptedPrivateKey);

                    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                    PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(decryptedPublicKeyBytes));
                    PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(decryptedPrivateKeyBytes));

                    return new KeyPair(publicKey, privateKey);
                } catch(Exception e){
                    throw new IncorrectPasswordException();
                }
            }
        }
        return null;
    }

    private byte[] getEncryptedKey(String path, String type){
        String beginning = "-----BEGIN PRIVATE KEY-----";
        String ending = "-----END PRIVATE KEY-----";
        if(type.equals("public")){
            beginning = "-----BEGIN PUBLIC KEY-----";
            ending = "-----END PUBLIC KEY-----";
        }

        Scanner sc = null;
        try {
            sc = new Scanner(new File(path));
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        }
        String aux = sc.nextLine();
        if(!aux.equals(beginning))
            return null;
        String txt = sc.nextLine();
        if(!sc.nextLine().equals(ending) || sc.hasNext())
            return null;
        sc.close();
        return Hex.decode(txt);
    }

    public VerificationMethodType getKeyTyp(){
        return VerificationMethodType.JSON_WEB_KEY_2020;
    }

    public ArrayList<String> listAlias(){
        File[] fileList = dir.listFiles();
        ArrayList<String> list = new ArrayList<>();
        for(File file: fileList){
            if(file.isDirectory() && validDir(file.getPath())){
                list.add(file.getName().split(" - ", 2)[1]);
            }
        }
        return list;
    }

    private boolean validDir(String path){
        File f = new File(path);
        File[] fileList = f.listFiles();
        if(fileList == null || fileList.length != 4){
            return false;
        }
        for(int i = 0; i < fileList.length; i++){
            if(!fileList[i].isFile() || !fileList[i].getName().equals(fileNames[i])){
                return false;
            }
        }
        return validMeta(fileList[3]);
    }

    private boolean validMeta(File f){
        try {
            Scanner sc = new Scanner(f);
            String line = sc.nextLine();
            return line.equals("RSA") && !sc.hasNext();
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        }
    }

    public void destroyKey(String alias, String password){
        File file = findKeyDir(alias);
        if(file.getName().equals(alias) && validDir(file.getPath())){
            try {
                desencriptarClavePrivada(password.toCharArray(), getEncryptedKey(file.getPath() + "\\enc-pubkey", "public"));
                desencriptarClavePrivada(password.toCharArray(), getEncryptedKey(file.getPath() + "\\enc-privkey", "private"));
                delete(file);
            } catch(Exception e){
                throw new IncorrectPasswordException();
            }
        }
    }

    private void delete(File f) throws IOException {
        if (f.isDirectory()) {
            File[] files = f.listFiles();
            for (File c : files)
                delete(c);
        }
        if (!f.delete())
            throw new FileNotFoundException("Failed to delete file: " + f);
    }

    public byte[] generateSeed(String mnemonic, String passphrase){
        return new SeedCalculator(JavaxPBKDF2WithHmacSHA512.INSTANCE).calculateSeed(mnemonic, passphrase);
    }

    private void createDir(String alias, KeyPair keyPair, String password, boolean recover){
        File newDir = new File(dir.getPath() + "\\" + alias);

        if(!recover && !newDir.mkdir() && validDir(newDir.getPath()))
            return;

        createFile(alias, "aliases", newDir);
        createFile(encryptPrivateKey(password, keyPair.getPrivate()), "enc-privkey", newDir);
        createFile(encryptPublicKey(password, keyPair.getPublic()), "enc-pubkey", newDir);
        createFile("RSA", "meta", newDir);
    }

    private void createFile(String content, String fileName, File dir){
        File f = new File(dir.getPath(), fileName);
        try {
            f.createNewFile();
            PrintWriter printWriter = new PrintWriter(f);
            printWriter.print(content);
            printWriter.close();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

    }

    private String encryptPrivateKey(String password, PrivateKey privateKey){
        try {
            byte[] tmp = encriptarClavePrivada(password.toCharArray(), privateKey.getEncoded());
            return "-----BEGIN PRIVATE KEY-----\n" + Hex.encode(tmp) + "\n-----END PRIVATE KEY-----";
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private String encryptPublicKey(String password, PublicKey publicKey){
        try {
            byte[] tmp = encriptarClavePrivada(password.toCharArray(), publicKey.getEncoded());
            return "-----BEGIN PUBLIC KEY-----\n" + Hex.encode(tmp) + "\n-----END PUBLIC KEY-----";
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private byte[] encriptarClavePrivada(char[] password, byte[] clavePrivada) throws Exception {
        byte[] salt = { (byte)0xc7, (byte)0x73, (byte)0x21, (byte)0x8c, (byte)0x7e, (byte)0xc8, (byte)0xee, (byte)0x99 };
        int iterations = 65536;
        int keyLength = 256;
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        KeySpec spec = new PBEKeySpec(password, salt, iterations, keyLength);
        SecretKey tmp = factory.generateSecret(spec);
        SecretKey secret = new SecretKeySpec(tmp.getEncoded(), "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        byte[] iv = { (byte)0x8d, (byte)0x0a, (byte)0x3e, (byte)0xee, (byte)0x25, (byte)0x7d, (byte)0x63, (byte)0xc1, (byte)0xaa, (byte)0x2b, (byte)0x61, (byte)0x9d, (byte)0xa3, (byte)0xf4, (byte)0x3e, (byte)0x33 };
        IvParameterSpec ivspec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, secret, ivspec);
        return cipher.doFinal(clavePrivada);
    }

    private byte[] desencriptarClavePrivada(char[] password, byte[] clavePrivadaEncriptada) throws Exception {
        byte[] salt = { (byte)0xc7, (byte)0x73, (byte)0x21, (byte)0x8c, (byte)0x7e, (byte)0xc8, (byte)0xee, (byte)0x99 };
        int iterations = 65536;
        int keyLength = 256;
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        KeySpec spec = new PBEKeySpec(password, salt, iterations, keyLength);
        SecretKey tmp = factory.generateSecret(spec);
        SecretKey secret = new SecretKeySpec(tmp.getEncoded(), "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        byte[] iv = { (byte)0x8d, (byte)0x0a, (byte)0x3e, (byte)0xee, (byte)0x25, (byte)0x7d, (byte)0x63, (byte)0xc1, (byte)0xaa, (byte)0x2b, (byte)0x61, (byte)0x9d, (byte)0xa3, (byte)0xf4, (byte)0x3e, (byte)0x33 };
        IvParameterSpec ivspec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, secret, ivspec);
        return cipher.doFinal(clavePrivadaEncriptada);
    }


    public static String generateJWKThumbprint(byte[] publicKeyBytes) throws NoSuchAlgorithmException {
        Map<String, String> jwkParams = new LinkedHashMap<>();
        jwkParams.put("crv", "Ed25519");
        jwkParams.put("kty", "OKP");
        jwkParams.put("x", Base64.getUrlEncoder().withoutPadding().encodeToString(publicKeyBytes));
        String jwk = "{" + jwkParams.entrySet().stream().map(entry -> "\"" + entry.getKey() + "\":\"" + entry.getValue() + "\"").reduce((s1, s2) -> s1 + "," + s2).orElse("") + "}";
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] thumbprintBytes = digest.digest(jwk.getBytes(StandardCharsets.UTF_8));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(thumbprintBytes);
    }

    public static boolean verifyJWKThumbprint(byte[] publicKeyBytes, String jwkThumbprint) throws NoSuchAlgorithmException {
        Map<String, String> jwkParams = new LinkedHashMap<>();
        jwkParams.put("crv", "Ed25519");
        jwkParams.put("kty", "OKP");
        jwkParams.put("x", Base64.getUrlEncoder().withoutPadding().encodeToString(publicKeyBytes));
        String jwk = "{" + jwkParams.entrySet().stream().map(entry -> "\"" + entry.getKey() + "\":\"" + entry.getValue() + "\"").reduce((s1, s2) -> s1 + "," + s2).orElse("") + "}";
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] thumbprintBytes = digest.digest(jwk.getBytes(StandardCharsets.UTF_8));
        String generatedThumbprint = Base64.getUrlEncoder().withoutPadding().encodeToString(thumbprintBytes);
        return generatedThumbprint.equals(jwkThumbprint);
    }

    private File findKeyDir(String alias){
        File[] listFiles = dir.listFiles();
        for(File f: listFiles){
            if(f.getName().matches("^[a-zA-Z0-9]{64} - " + alias))
                return f;
        }
        return null;
    }

    public File getDir(){ return dir; }


}
