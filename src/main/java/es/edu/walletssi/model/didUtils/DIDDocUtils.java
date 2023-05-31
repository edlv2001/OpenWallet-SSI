package es.edu.walletssi.model.didUtils;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.util.Pair;
import es.edu.walletssi.key.utils.KeyUtils;
import foundation.identity.did.DIDDocument;
import foundation.identity.did.VerificationMethod;
import io.fusionauth.pem.domain.PEM;
import io.ipfs.multibase.Base58;
import io.ipfs.multibase.Multibase;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.didcommx.didcomm.common.VerificationMaterial;
import org.didcommx.didcomm.common.VerificationMaterialFormat;
import org.didcommx.didcomm.common.VerificationMethodType;
import org.didcommx.didcomm.diddoc.DIDCommService;
import org.didcommx.didcomm.diddoc.DIDDoc;

import java.security.PublicKey;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class DIDDocUtils {

    public static PublicKey getNKey(DIDDocument didDocument, int n){
        if(n < 0) return null;
        List<VerificationMethod> verificationMethod = didDocument.getVerificationMethods();
        if(n >= verificationMethod.size()) return null;
        VerificationMethod v = verificationMethod.get(n);
        return publicKeyFromVerificationMethod(v);
    }

    public static int findKey(DIDDocument didDocument, PublicKey publicKey){
        List<VerificationMethod> list = didDocument.getVerificationMethods();
        for(int i = 0; i < list.size(); i++){
            VerificationMethod v = list.get(i);
            PublicKey keyN = publicKeyFromVerificationMethod(v);
            if(publicKey.getAlgorithm().equals(keyN.getAlgorithm())
                    && Arrays.equals(publicKey.getEncoded(), keyN.getEncoded())){
                return i;
            }
        }
        return -1;
    }

    public static PublicKey publicKeyFromVerificationMethod(VerificationMethod verificationMethod){
        if(verificationMethod.getPublicKeyJwk() != null){
            try {
                JWK jwk = JWK.parse(verificationMethod.getPublicKeyJwk());
                try {
                    return jwk.toECKey().toPublicKey();
                } catch (Exception e) {}
                try {
                    return KeyUtils.publicJwkToKeyEC25519(jwk.toOctetKeyPair());
                } catch (Exception e) {}
                try {
                    return jwk.toRSAKey().toPublicKey();
                } catch (Exception e) {}
                try {
                    return jwk.toOctetSequenceKey().toECKey().toPublicKey();
                } catch (Exception e) {}
            } catch (ParseException e) {
                throw new RuntimeException(e);
            }
            return null;
        }
        if(verificationMethod.getPublicKeyBase58() != null) {
            return new PublicKeyJWK(Base58.decode(verificationMethod.getPublicKeyBase58()), verificationMethod.getType(), null);
        }
        if(verificationMethod.getPublicKeyBase64() != null){
            return new PublicKeyJWK(Base64.decode(verificationMethod.getPublicKeyBase64()), verificationMethod.getType(), null);
        }
        if(verificationMethod.getPublicKeyHex() != null){
            return new PublicKeyJWK(Hex.decode(verificationMethod.getPublicKeyHex()), verificationMethod.getType(), null);
        }
        if(verificationMethod.getPublicKeyMultibase() != null){
            return new PublicKeyJWK(Multibase.decode(verificationMethod.getPublicKeyMultibase()), verificationMethod.getType(), null);
        }
        if(verificationMethod.getPublicKeyPem() != null){
            return new PublicKeyJWK(PEM.decode(verificationMethod.getPublicKeyPem()).getPublicKey().getEncoded(), verificationMethod.getType(), null);
        }
        return null;
    }

    static class PublicKeyJWK implements PublicKey{
        private byte[] encoded;
        private String algorithm;
        private String format;

        public PublicKeyJWK(byte[] encoded, String algorithm, String format){
            this.encoded = encoded;
            this.algorithm = algorithm;
            this.format = format;
        }

        @Override
        public String getAlgorithm() {
            return algorithm;
        }

        @Override
        public String getFormat() {
            return format;
        }

        @Override
        public byte[] getEncoded() {
            return encoded;
        }
    }


    public static DIDDoc transformDIDDoc(DIDDocument didDocument, String did){
        List<String> keyAgreements = new ArrayList<>();
        try{
            for(VerificationMethod verificationMethod : didDocument.getKeyAgreementVerificationMethods(true)){
                keyAgreements.add(verificationMethod.toJson(true));
            }
        } catch (NoSuchMethodError | Exception e){}
        List<String> authentications = new ArrayList<>();
        try{
            for(VerificationMethod verificationMethod: didDocument.getAuthenticationVerificationMethods()){
                authentications.add(verificationMethod.toJson(true));
            }
        } catch (NoSuchMethodError | Exception e){}
        List<org.didcommx.didcomm.diddoc.VerificationMethod> verificationMethods = new ArrayList<>();
        for(VerificationMethod verificationMethod: didDocument.getVerificationMethods()){
            Pair<VerificationMaterialFormat, String> pair = getFormat(verificationMethod);
            VerificationMaterial material = new VerificationMaterial(pair.getLeft(), pair.getRight());
            VerificationMethodType type = getType(verificationMethod);
            org.didcommx.didcomm.diddoc.VerificationMethod v =
                    new org.didcommx.didcomm.diddoc.VerificationMethod(
                            verificationMethod.getId().toString(),
                            type,
                            material,
                            verificationMethod.getController()
                    );
            verificationMethods.add(v);
        }
        List<DIDCommService> didCommServices = new ArrayList<>();

        return new DIDDoc(did, keyAgreements, authentications, verificationMethods, didCommServices);
    }

    /*private VerificationMaterialFormat getFormat(VerificationMethod verificationMethod){
        if(verificationMethod.getPublicKeyBase58() != null) return VerificationMaterialFormat.BASE58;
        if(verificationMethod.getPublicKeyJwk() != null) return VerificationMaterialFormat.JWK;
        if(verificationMethod.getPublicKeyMultibase() != null) return VerificationMaterialFormat.MULTIBASE;
        return VerificationMaterialFormat.OTHER;
    }*/

    private static Pair<VerificationMaterialFormat, String> getFormat(VerificationMethod verificationMethod){
        if(verificationMethod.getPublicKeyBase58() != null)
            return Pair.of(VerificationMaterialFormat.BASE58, verificationMethod.getPublicKeyBase58());
        if(verificationMethod.getPublicKeyJwk() != null) {
            try {
                return Pair.of(VerificationMaterialFormat.JWK, JWK.parse(verificationMethod.getPublicKeyJwk()).toJSONString());
            } catch (ParseException e) {
                throw new RuntimeException(e);
            }
        }
        if(verificationMethod.getPublicKeyMultibase() != null)
            return Pair.of(VerificationMaterialFormat.MULTIBASE, verificationMethod.getPublicKeyMultibase());
        if(verificationMethod.getPublicKeyBase64() != null)
            return Pair.of(VerificationMaterialFormat.OTHER, verificationMethod.getPublicKeyBase64());
        if(verificationMethod.getPublicKeyHex() != null)
            return Pair.of(VerificationMaterialFormat.OTHER,verificationMethod.getPublicKeyHex());
        if(verificationMethod.getPublicKeyPem() != null)
            return Pair.of(VerificationMaterialFormat.OTHER, verificationMethod.getPublicKeyPem());
        return null;
    }

    private static VerificationMethodType getType(VerificationMethod verificationMethod){
        try {
            return VerificationMethodType.valueOf(verificationMethod.getType().toUpperCase());
        } catch(Exception e){
            if(verificationMethod.getType().equals("JsonWebKey2020"))
                return VerificationMethodType.JSON_WEB_KEY_2020;
        }
        return null;
    }
}
