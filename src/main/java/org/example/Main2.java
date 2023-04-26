package org.example;

import org.example.walletssi.Wallet;
import org.example.walletssi.key.KeyHandlerEd25519;

import java.security.KeyPair;
import java.util.Arrays;

public class Main2 {
    public static void main(String[] args){
        String alias = "key4";
        Wallet w = new Wallet();
        w.genKey("hola", "password");

        /*KeyHandlerEd25519 keyHandlerEd25519 = new KeyHandlerEd25519(".\\data\\key");


        KeyPair keyPair = keyHandlerEd25519.generateKeys(keyHandlerEd25519.generateSeed(keyHandlerEd25519.generateMnemonic(), ""));



        System.out.println("Private : " +Arrays.toString(keyPair.getPrivate().getEncoded()));
        System.out.println("Public : " +Arrays.toString(keyPair.getPublic().getEncoded()));

        keyHandlerEd25519.storeKey(keyPair, alias, password);

        System.out.println(keyHandlerEd25519.listAlias());

        KeyPair keyPair1 = keyHandlerEd25519.obtainKey(alias);
        System.out.println("Private : " +Arrays.toString(keyPair1.getPrivate().getEncoded()));
        System.out.println("Public : " +Arrays.toString(keyPair1.getPublic().getEncoded()));


        keyHandlerEd25519.destroyKey(alias, "holaxd");


        keyPair.getPrivate().getEncoded();
        byte[] privateKey = keyPair.getPrivate().getEncoded();
        byte[] publicKey = keyPair.getPublic().getEncoded();
        byte[] signData = new byte[64];
        System.arraycopy(privateKey, 0, signData, 0, 32);
        System.arraycopy(publicKey, 0, signData, 32, 32);

        //Wallet w = new Wallet();
        //w.genKey();*/
    }
}
