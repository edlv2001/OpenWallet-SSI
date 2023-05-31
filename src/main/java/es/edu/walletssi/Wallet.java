package es.edu.walletssi;

import com.danubetech.verifiablecredentials.VerifiableCredential;
import com.danubetech.verifiablecredentials.VerifiablePresentation;
import es.edu.walletssi.key.KeyHandler;
import es.edu.walletssi.key.KeyType;
import es.edu.walletssi.model.DidMethod;
import es.edu.walletssi.model.handlers.DidMethodHandler;
import es.edu.walletssi.model.vc.VerifiableCredentialIssuer;
import es.edu.walletssi.model.vc.VerifiableCredentialVerifier;
import es.edu.walletssi.model.vc.VerifiablePresentationCreator;
import es.edu.walletssi.model.vc.VerifiablePresentationVerifier;
import es.edu.walletssi.model.vc.signature.Signature;
import foundation.identity.did.DIDDocument;

import foundation.identity.jsonld.JsonLDObject;

import java.net.URI;
import java.security.*;
import java.util.*;

import org.didcommx.didcomm.DIDComm;
import es.edu.walletssi.init.WalletConfiguration;
import org.jetbrains.annotations.NotNull;
import org.springframework.web.client.RestTemplate;

public class Wallet {
    private KeyHandler[] keyHandler;
    private DidMethodHandler didMethodHandler;
    private VerifiableCredentialIssuer vcIssuer;
    private VerifiableCredentialVerifier vcVerifier;
    private VerifiablePresentationCreator vpCreator;
    private VerifiablePresentationVerifier vpVerifier;
    private DIDComm didComm;
    private WalletConfiguration walletConfiguration;


    public Wallet(WalletConfiguration config){
        this.walletConfiguration = config;
        this.didMethodHandler = DidMethod.getHandlerInit(config.getDidMethod(), config.getDidMethodHandlerConfig());

        keyHandler = KeyType.keyHandlers(config.getKeyStorePath());
        vcIssuer = new VerifiableCredentialIssuer(config.getVcCreatedPath(), config.getVcOwnedPath());
        vcVerifier = new VerifiableCredentialVerifier();
        vpCreator = new VerifiablePresentationCreator(config.getVpStorePath());
        vpVerifier = new VerifiablePresentationVerifier();

    }
    public String genKey(String alias, String password, KeyType type){
        return genKey("", alias, password, type);
    }

    public String genKey(String passphrase, String alias, String password, KeyType type){
        String mnemonic = keyHandler[type.ordinal()].generateMnemonic();
        KeyPair keyPair = this.keyHandler[type.ordinal()].generateKeys(
                keyHandler[type.ordinal()].generateSeed(mnemonic, passphrase)
        );
        this.keyHandler[type.ordinal()].storeKey(keyPair, alias, password);
        return mnemonic;
    }

    public boolean recoverPassword(String alias, String newPassword, String mnemonic, KeyType keyType){
        return recoverPassword(alias, newPassword, mnemonic, "", keyType);
    }

    public boolean recoverPassword(String alias, String newPassword, String mnemonic, String passphrase, KeyType keyType){
        KeyPair keyPair = this.keyHandler[keyType.ordinal()].generateKeys(
                keyHandler[keyType.ordinal()].generateSeed(mnemonic, passphrase)
        );
        return keyHandler[keyType.ordinal()].recoverKey(keyPair, alias, newPassword);
    }


    public String genDID(PublicKey publicKey){
        return this.didMethodHandler.genDID(publicKey);
    }

    public List<String> listKeyAlias(KeyType keyType){ return this.keyHandler[keyType.ordinal()].listAlias(); }

    public KeyPair getKeys(String alias, String password, KeyType keyType){
        return this.keyHandler[keyType.ordinal()].obtainKey(alias, password);
    }

    public String issueVC(Map<String, Object> claims, String didIssuer, KeyPair keyPair, String didSubject, Date expirationDate, boolean store){
        DIDDocument didDocument = DIDDocument.fromJson(this.didMethodHandler.getDidDocFromFile(didIssuer));
        VerifiableCredential vc = vcIssuer.issue(claims, didIssuer, didSubject, expirationDate, store);
        String signed = vcIssuer.signVC(vc, keyPair, didIssuer, didDocument);
        return signed;

    }

    public String issueVC(@NotNull URI schema, String type, Map<String, Object> claims, String didIssuer, KeyPair keyPair, String didSubject, Date expirationDate, boolean store){
        DIDDocument didDocument = DIDDocument.fromJson(this.didMethodHandler.getDidDocFromFile(didIssuer));
        VerifiableCredential vc = vcIssuer.issue(schema.toString(), type, claims, didIssuer, didSubject, expirationDate, store);

        return vcIssuer.signVC(vc, keyPair, didIssuer, didDocument);
    }


    public boolean verifyVC(String vc, boolean fromTrustedRegistry){
        return this.vcVerifier.verify(vc, walletConfiguration.getDidMethodHandlerConfig(), fromTrustedRegistry);
    }

    public boolean verifyVCWithoutRegistry(String vc){
        return this.vcVerifier.verifyWithoutRegistry(vc, walletConfiguration.getDidMethodHandlerConfig());
    }

    public String issueVP(String vc, String didHolder, KeyPair keyPair, Date expirationDate, boolean store){
        DIDDocument didDocument = DIDDocument.fromJson(this.didMethodHandler.getDidDocFromFile(didHolder));

        VerifiablePresentation vp = vpCreator.issueVP(vc, didHolder, store);
        String signed = vpCreator.signVP(vp, keyPair, didHolder, didDocument);

        return signed;
    }

    public String issueVP(@NotNull URI schema, String type, String vc, String didHolder, KeyPair keyPair, Date expirationDate, boolean store){
        DIDDocument didDocument = DIDDocument.fromJson(this.didMethodHandler.getDidDocFromFile(didHolder));

        VerifiablePresentation vp = vpCreator.issueVP(schema.toString(), type, vc, didHolder, store);
        String signed = vpCreator.signVP(vp, keyPair, didHolder, didDocument);

        return signed;
    }

    public boolean verifyVP(String vp, boolean fromTrustedRegistry){
        return this.vpVerifier.verify(vp, walletConfiguration.getDidMethodHandlerConfig(), fromTrustedRegistry);
    }

    public boolean verifyVPWithoutRegistry(String vp){
        return this.vpVerifier.verifyWithoutRegistry(vp, walletConfiguration.getDidMethodHandlerConfig());
    }

    public boolean verifyVPWithOnlyVCSchema(String vp, boolean fromTrustedRegistry){
        return this.vpVerifier.verifyWithOnlyVCSchema(vp, walletConfiguration.getDidMethodHandlerConfig(), fromTrustedRegistry);
    }

    public void storeVC(@NotNull String vc){
        vcIssuer.storeVc(vc);
    }

    public List<String> listDIDs(){
        return this.didMethodHandler.listDids();
    }

    public List<String> listCreatedVc(String schema){
        return vcIssuer.listCreatedVC(schema);
    }
    public List<String> listCreatedVc(){
        return vcIssuer.listCreatedVC(null);
    }
    public List<String> listCreatedVc(URI schemaURI){
        RestTemplate restTemplate = new RestTemplate();
        String schema = restTemplate.getForObject(schemaURI, String.class);
        if(schema == null || schema.isEmpty()){
            return List.of();
        }
        return listCreatedVc(schema);
    }

    public List<String> listOwnedVc(String schema){
        return vcIssuer.listOwnedVC(schema);
    }
    public List<String> listOwnedVc(){
        return vcIssuer.listOwnedVC(null);
    }
    public List<String> listOwnedVc(URI schemaURI){
        RestTemplate restTemplate = new RestTemplate();
        String schema = restTemplate.getForObject(schemaURI, String.class);
        if(schema == null || schema.isEmpty()){
            return List.of();
        }
        return listOwnedVc(schema);
    }

    public List<String> listStoredVp(String schema){
        return vpCreator.listVP(schema);
    }
    public List<String> listStoredVp(){
        return vpCreator.listVP(null);
    }
    public List<String> listStoredVp(URI schemaURI){
        RestTemplate restTemplate = new RestTemplate();
        String schema = restTemplate.getForObject(schemaURI, String.class);
        if(schema == null || schema.isEmpty()){
            return List.of();
        }
        return listStoredVp(schema);
    }

    public String sign(Map<String, Object> json, @NotNull KeyPair keyPair, String did){
        return Signature.signJsonLD(JsonLDObject.fromJsonObject(json),
                keyPair,
                did,
                DIDDocument.fromJson(didMethodHandler.getDidDocFromFile(did))
        );
    }

    public String getStoredDidDocument(String did){
        return didMethodHandler.getDidDocFromFile(did);

    }

    public String getStoredVP(String vpName){
        return vpCreator.getVP(vpName);
    }

    public String getOwnedVC(String vcName){
        return vcIssuer.getOwnedVC(vcName);
    }

    public String getCreatedVC(String vcName){
        return vcIssuer.getCreatedVC(vcName);
    }

}
