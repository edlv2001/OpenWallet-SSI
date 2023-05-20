package org.example.walletssi;

import com.danubetech.keyformats.crypto.ByteSigner;
import com.danubetech.keyformats.crypto.impl.Ed25519_EdDSA_PrivateKeySigner;
import com.danubetech.verifiablecredentials.VerifiableCredential;
import com.danubetech.verifiablecredentials.VerifiablePresentation;
import com.danubetech.verifiablecredentials.jwt.JwtVerifiableCredential;
import com.danubetech.verifiablecredentials.jwt.ToJwtConverter;
import com.google.crypto.tink.subtle.Hex;
import com.nimbusds.jose.JOSEException;
import foundation.identity.did.DIDDocument;
import id.walt.crypto.Key;

import id.walt.services.keystore.KeyStoreService;
import id.walt.signatory.*;
import io.github.novacrypto.bip39.*;

import java.io.File;
import java.security.*;
import java.util.*;

import org.didcommx.didcomm.DIDComm;
import org.didcommx.didcomm.message.Message;
import org.didcommx.didcomm.model.PackPlaintextParams;
import org.didcommx.didcomm.model.PackPlaintextResult;
import org.didcommx.didcomm.model.UnpackParams;
import org.didcommx.didcomm.model.UnpackResult;
import org.example.walletssi.init.WalletConfiguration;
import org.example.walletssi.key.KeyHandler;
import org.example.walletssi.key.KeyHandlerEd25519;
import org.example.walletssi.key.secret.SecretResolverDefault;
import org.example.walletssi.key.utils.KeyUtils;
import org.example.walletssi.model.DidMethod;
import org.example.walletssi.model.handlers.DidMethodHandler;
import org.example.walletssi.model.handlers.EBSIMethodHandler;
import org.example.walletssi.model.handlers.KeyMethodHandler;
import org.example.walletssi.model.vc.VerifiableCredentialIssuer;
import org.example.walletssi.model.vc.VerifiableCredentialVerifier;
import org.example.walletssi.model.vc.VerifiablePresentationCreator;
import org.example.walletssi.model.vc.VerifiablePresentationVerifier;

public class Wallet {

    //private final KeyService keyService = KeyService.Companion.getService();
    //private final KeyStoreService keyService = EncryptedKeyStore.Companion.getService();
    //private final ServiceMatrix serviceMatrix= new ServiceMatrix("service-matrix.properties");

    private KeyHandler keyHandler;


    private DidMethodHandler didMethodHandler;

    private VerifiableCredentialIssuer vcIssuer;

    private VerifiableCredentialVerifier vcVerifier;

    private VerifiablePresentationCreator vpCreator;

    private VerifiablePresentationVerifier vpVerifier;

    private DIDComm didComm;

    private WalletConfiguration walletConfiguration;


    public Wallet(WalletConfiguration config){
        this.walletConfiguration = config;
        this.didMethodHandler = DidMethod.getHandler(config.getDidMethod(), config.getDidMethodHandlerConfig());

        keyHandler = new KeyHandlerEd25519(config.getKeyStorePath());
        vcIssuer = new VerifiableCredentialIssuer();
        vcVerifier = new VerifiableCredentialVerifier();
        vpCreator = new VerifiablePresentationCreator();
        vpVerifier = new VerifiablePresentationVerifier();

    }

    /*
    public void genKey(String passphrase){
        //MnemonicGenerator mnemonicGenerator = new MnemonicGenerator(English.INSTANCE);
        StringBuilder sb = new StringBuilder();
        byte[] entropy = new byte[Words.FIFTEEN.byteLength()];
        new SecureRandom().nextBytes(entropy);
        new MnemonicGenerator(English.INSTANCE)
                .createMnemonic(entropy, sb::append);
        String mnemonic = sb.toString();
        AsymmetricCipherKeyPair keyPair = keyPairFromSeed(generateSeed(mnemonic,passphrase));
        //KeyPair keyPair = keyPairFromSeed(generateSeed(mnemonic, passphrase));
        /*System.out.println("Private key bytes: " + Arrays.toString(keyPair.getPrivate().getEncoded()));
        PrivateKey privateKey = keyPair.getPrivate();

        String privateKeyString = bytesToHex(privateKey.getEncoded());
        System.out.println("Clave privada: " + privateKeyString);

        PublicKey publicKey = keyPair.getPublic();
        System.out.println(privateKey.getEncoded().length);
        System.out.println("Public key bytes: " + Arrays.toString(keyPair.getPublic().getEncoded()));
        System.out.println(publicKey.getEncoded().length);

        String publicKeyString = bytesToHex(publicKey.getEncoded());
        System.out.println("Clave pública: " + publicKeyString);
*/


        /*byte[] testEd25519PrivateKey = new byte[0];
        try {
            testEd25519PrivateKey = Hex.decodeHex("984b589e121040156838303f107e13150be4a80fc5088ccba0b0bdc9b1d89090de8777a28f8da1a74e7a13090ed974d879bf692d001cddee16e4cc9f84b60580".toCharArray());
        } catch (DecoderException e) {
            throw new RuntimeException(e);
        }
        System.out.println(testEd25519PrivateKey.length);*/

/*
        Map<String, Object> claims = new LinkedHashMap<>();
        Map<String, Object> degree = new LinkedHashMap<String, Object>();
        degree.put("name", "Bachelor of Science and Arts");
        degree.put("type", "BachelorDegree");
        claims.put("college", "Test University");
        claims.put("degree", degree);

        CredentialSubject credentialSubject = CredentialSubject.builder()
                .id(URI.create("did:example:ebfeb1f712ebc6f1c276e12ec21"))
                .claims(claims)
                .build();

        VerifiableCredential verifiableCredential = VerifiableCredential.builder()
                .context(VerifiableCredentialContexts.JSONLD_CONTEXT_W3C_2018_CREDENTIALS_EXAMPLES_V1)
                .type("UniversityDegreeCredential")
                .id(URI.create("http://example.edu/credentials/3732"))
                .issuer(URI.create("did:example:76e12ec712ebc6f1c221ebfeb1f"))
                .issuanceDate(JsonLDUtils.stringToDate("2019-06-16T18:56:59Z"))
                .expirationDate(JsonLDUtils.stringToDate("2019-06-17T18:56:59Z"))
                .credentialSubject(credentialSubject)
                .build();


       // byte[] priv = Base58.decode(privateKeyString);
        //byte[] pub = Base58.decode(publicKeyString);




        Ed25519PrivateKeyParameters privateKeyParams = (Ed25519PrivateKeyParameters) keyPair.getPrivate();
        Ed25519PublicKeyParameters publicKeyParams = (Ed25519PublicKeyParameters) keyPair.getPublic();

        byte[] privateKey = privateKeyParams.getEncoded();
        byte[] publicKey = publicKeyParams.getEncoded();

        com.nimbusds.jose.JWSAlgorithm jwsAlgorithm = JWSAlgorithm.EdDSA;
        jwsAlgorithm.toJSONString();


        byte[] signData = new byte[64];
        System.arraycopy(privateKey, 0, signData, 0, 32);
        System.arraycopy(publicKey, 0, signData, 32, 32);



        String privateKeyString = Hex.encodeHexString(privateKeyParams.getEncoded());
        System.out.println("xd: " + privateKeyString);
        System.out.println("xd.length" + privateKeyString.length());
        System.out.println(stringToBytes(Wallet.convertPrivateKeyToHex(privateKeyParams.getEncoded())).length);

        byte[] priv = new byte[0];
        try {
            priv = Hex.decodeHex(Wallet.convertPrivateKeyToHex(privateKeyParams.getEncoded()).toCharArray());
        } catch (DecoderException e) {
            throw new RuntimeException(e);
        }
        //priv = stringToBytes(bytesToHex(privateKey.getEncoded()));

        //info.weboftrust.ldsignatures.signer.Ed25519Signature2020LdSigner signer = new Ed25519Signature2020LdSigner(privateKey.getEncoded());

        /*try {
            signer.sign(verifiableCredential);
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        } catch (JsonLDException e) {
            throw new RuntimeException(e);
        }*/

        /**
        Ed25519Signature2018LdSigner ldSigner = new Ed25519Signature2018LdSigner(signData);
        try {
            ldSigner.sign(verifiableCredential, true, true);
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        } catch (JsonLDException e) {
            throw new RuntimeException(e);
        }*/

/*
        String jwtString = signJWT(verifiableCredential, privateKey, publicKey);
        System.out.println("jwt: " + jwtString);
        //publicKey[0] = 0;
        JwtVerifiableCredential jwt =null;
        try {
            jwt = JwtVerifiableCredential.fromCompactSerialization(jwtString);


            //jwt.sign_Ed25519_EdDSA(new Ed25519_EdDSA_PrivateKeySigner(signData));
            System.out.println(jwt.verify_Ed25519_EdDSA(publicKey));
        } catch (ParseException e) {
            throw new RuntimeException(e);
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }


        VerifiableCredential vc = FromJwtConverter.fromJwtVerifiableCredential(jwt);
        System.out.println(vc.toJson());
        System.out.println(verifiableCredential.toJson());
        //byte[] pub = stringToBytes(bytesToHex(publicKey.getEncoded()));
/*
        Ed25519Signature2018LdVerifier verifier = new Ed25519Signature2018LdVerifier(publicKey);

        try {
            System.out.println(verifier.verify(verifiableCredential));
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        } catch (JsonLDException e) {
            throw new RuntimeException(e);
        }
*/







   // }


    public String genKey(String alias, String password){
        return genKey("", alias, password);
    }

    public String genKey(String passphrase, String alias, String password){
        String mnemonic = keyHandler.generateMnemonic();
        KeyPair keyPair = this.keyHandler.generateKeys(
                keyHandler.generateSeed(mnemonic, passphrase)
        );
        this.keyHandler.storeKey(keyPair, alias, password);


        /*this.keyHandler.storeKey(
                this.keyHandler.generateKeys(
                        keyHandler.generateSeed(mnemonic, passphrase)
                ), alias, password
        );*/
        /*System.out.println(this.ebsiMethodHandler.genDID(keyPair.getPublic()));

        List<String> dids = ebsiMethodHandler.listDids();
        for(int i = 0; i < dids.size(); i++){
            System.out.println(ebsiMethodHandler.getDidDoc(dids.get(i)));
        }*/
        //String did = this.keyMethodHandler.genDID(keyPair.getPublic());
        //System.out.println(did);
        //System.out.println(this.keyMethodHandler.generateDidDocument(did));
        return mnemonic;
    }

    public boolean recoverPassword(String alias, String newPassword, String mnemonic){
        return recoverPassword(alias, newPassword, mnemonic, "");
    }

    public boolean recoverPassword(String alias, String newPassword, String mnemonic, String passphrase){
        KeyPair keyPair = this.keyHandler.generateKeys(
                keyHandler.generateSeed(mnemonic, passphrase)
        );


        System.out.println("Public: " + Hex.encode(keyPair.getPublic().getEncoded()));
        System.out.println("Private: " + Hex.encode(keyPair.getPrivate().getEncoded()));

        return keyHandler.recoverKey(keyPair, alias, newPassword);
    }


    public String genDID(PublicKey publicKey){
        return this.didMethodHandler.genDID(publicKey);
    }

    public KeyPair getKeys(String alias, String password){
        return this.keyHandler.obtainKey(alias, password);
    }

    private byte[] generateSeed(String mnemonic, String passphrase){
        return new SeedCalculator(JavaxPBKDF2WithHmacSHA512.INSTANCE).calculateSeed(mnemonic, passphrase);
    }








    /*public void validateKeys(byte[] privateKey, byte[] publicKey){
        RSAPrivateCrtKeyImpl rsaPrivateKey = (RSAPrivateCrtKeyImpl)privateKey;
        try {
            PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(rsaPrivateKey.getModulus(), rsaPrivateKey.getPublicExponent()));
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

    }*/





    /*public void run(){
        new ServiceMatrix("service-matrix.properties");

        /*KeyId keyId = keyService.generate(KeyAlgorithm.EdDSA_Ed25519);
        System.out.println("EBSI key generated: " + keyId);*/

        //String did = DidService.INSTANCE.create(DidMethod.key, keyId.getId(), null);

        //String didEbsi = DidService.INSTANCE.create(DidMethod.ebsi, keyId.getId(), null);

/*

        List<Key> listKeys = keyService.listKeys();
        for(int i = 0; i < listKeys.size(); i++)
            System.out.println(listKeys.get(i));
        listKeys.get(0).getKeyPair().getPrivate();
        List<String> listDids = DidService.INSTANCE.listDids();
        /*for(int i = 0; i < l2.size(); i++)
            System.out.println(l2.get(i));
        String did;
        if(listKeys.isEmpty()){
            did = generateDid(id.walt.model.DidMethod.key);
        } else if (listDids.isEmpty()) {
            did = generateDid(id.walt.model.DidMethod.key, selectKey(listKeys));
        } else {
            did = listDids.get(0);
        }


        System.out.println(did);
        Did didDoc = DidService.INSTANCE.load(did);
        System.out.println(didDoc.encodePretty());
        Did didDoc2 = DidService.INSTANCE.resolve(did);



        System.out.println(didDoc2.encodePretty());

        issue(did);
    }

    public VerifiableCredential issue(Map<String, Object> claims, String did){
        CredentialSubject credentialSubject = CredentialSubject.builder()
                .id(URI.create("did:example:ebfeb1f712ebc6f1c276e12ec21"))
                .claims(claims)
                .build();

        VerifiableCredential verifiableCredential = VerifiableCredential.builder()
                .context(VerifiableCredentialContexts.JSONLD_CONTEXT_W3C_2018_CREDENTIALS_EXAMPLES_V1)
                .type("UniversityDegreeCredential")
                .id(URI.create("http://example.edu/credentials/3732"))
                .issuer(URI.create("did:example:76e12ec712ebc6f1c221ebfeb1f"))
                .issuanceDate(JsonLDUtils.stringToDate("2019-06-16T18:56:59Z"))
                .expirationDate(JsonLDUtils.stringToDate("2019-06-17T18:56:59Z"))
                .credentialSubject(credentialSubject)
                .build();
    }
    */

    public ProofConfig createProofConfig(String issuerDid, String subjectDid, ProofType proofType, String dataProviderIdentifier) {
        return new ProofConfig(issuerDid, subjectDid, null, null, proofType, null, null,
                null, null, null, null, null, dataProviderIdentifier, null , null, Ecosystem.DEFAULT  );
    }

    public PackPlaintextResult createMessage(Map<String, ? extends  Object> claims, String type){
        Message message = Message.Companion.builder(
                UUID.randomUUID().toString(),
                claims,
                type
        ).build();

        PackPlaintextParams packPlaintextParams = new PackPlaintextParams(message, null, didMethodHandler.getResolver(), new SecretResolverDefault(this.keyHandler));
        PackPlaintextResult packPlaintextResult = didComm.packPlaintext(packPlaintextParams);
        return packPlaintextResult;
    }

    public void sendMessage(){

    }

    public Object processMessage(PackPlaintextResult message){
        UnpackResult result = didComm.unpack(new UnpackParams.Builder(message.getPackedMessage()).build());

        return null;
    }

    public String issueVC(Map<String, Object> claims, String didIssuer, KeyPair keyPair, String didSubject, Date expirationDate){
        DIDDocument didDocument = DIDDocument.fromJson(this.didMethodHandler.getDidDoc(didIssuer));
        System.out.println(didDocument.toJson(true));
        VerifiableCredential vc = vcIssuer.issue(claims, didIssuer, didSubject, keyPair, expirationDate);
        String signed = vcIssuer.signVC(vc, keyPair, didIssuer, didDocument);
        System.out.println(signed);

        return signed;

    }

    public boolean verifyVC(String vc){
        return this.vcVerifier.verify(vc);
    }

    public boolean verifyVCWithoutRegistry(String vc){
        return this.vcVerifier.verifyWithoutRegistry(vc, walletConfiguration.getDidMethodHandlerConfig());
    }

    public String issueVP(String vc, String didHolder, KeyPair keyPair, Date expirationDate){
        DIDDocument didDocument = DIDDocument.fromJson(this.didMethodHandler.getDidDoc(didHolder));

        VerifiablePresentation vp = vpCreator.issueVP(vc, didHolder);
        String signed = vpCreator.signVP(vp, keyPair, didHolder, didDocument);


        return signed;

    }

    public boolean verifyVP(String vp){
        return this.vpVerifier.verify(vp);
    }

    public boolean verifyVPWithoutRegistry(String vp){
        return this.vpVerifier.verifyWithoutRegistry(vp, walletConfiguration.getDidMethodHandlerConfig());
    }

}
