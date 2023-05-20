package org.example.walletssi.model.resolver;

import foundation.identity.did.DIDDocument;
import org.didcommx.didcomm.common.VerificationMaterial;
import org.didcommx.didcomm.common.VerificationMaterialFormat;
import org.didcommx.didcomm.common.VerificationMethodType;
import org.didcommx.didcomm.diddoc.DIDCommService;
import org.didcommx.didcomm.diddoc.DIDDoc;
import org.didcommx.didcomm.diddoc.DIDDocResolver;
import org.didcommx.didcomm.diddoc.VerificationMethod;
import org.didcommx.didcomm.message.Message;
import org.example.walletssi.model.didUtils.DIDDocImp;
import org.example.walletssi.model.didUtils.DIDDocUtils;
import org.example.walletssi.model.didUtils.DIDParser;
import org.example.walletssi.model.handlers.config.DidMethodHandlerConfig;
import org.example.walletssi.model.handlers.config.EBSIMethodHandlerConfig;
import org.jetbrains.annotations.NotNull;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;


import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

public class EBSIDIDDocResolver implements DIDDocResolver, DIDResolver {

    private URI didRegistry;

    public EBSIDIDDocResolver(EBSIMethodHandlerConfig config) {
        this.didRegistry = URI.create(config.getDidRegistry());
    }

    @NotNull
    @Override
    public Optional<DIDDoc> resolve(@NotNull String did) {
        if (!DIDParser.isValid(did, org.example.walletssi.model.DidMethod.EBSI)) {
            return null;
        }
        RestTemplate restTemplate = new RestTemplate();
        System.out.println("didRegistry: " + didRegistry + "/did");
        ResponseEntity<String> response = restTemplate.getForEntity(didRegistry + "/did?did=" + did, String.class);
        if (response == null || response.getBody() == null || response.getBody().isEmpty()) {
            return null;
        }

        System.out.println("\n\n\n\n" + response.getBody());

        //DIDDoc didDoc = fromJson(response.getBody(), did);
        try {
            //DIDDocument didDocument = DIDDocument.fromJson(response.getBody());
            DIDDocImp didDocImp = DIDDocImp.Companion.fromJson(response.getBody());
            DIDDoc decodedDoc = new DIDDoc(did, didDocImp.getKeyAgreements(), didDocImp.getAuthentications(), didDocImp.getVerificationMethods(), didDocImp.getDidCommServices());

            //DIDDoc decodedDoc = DIDDocParser.DIDDocDecoder.parseDIDDoc(response.getBody());


            //DIDDoc decodedDoc = DIDDocUtils.transformDIDDoc(didDocument, did);


           /* // Obtener la clase DIDDoc
            Class<?> didDocClass = Class.forName("org.didcommx.didcomm.diddoc.DIDDoc");


            for(Field f : didDocClass.getDeclaredFields()){
                System.out.println(f.getName());
            }

            for(Class c: didDocClass.getDeclaredClasses()){
                System.out.println(c.getName());
            }

            for(Method m: didDocClass.getDeclaredMethods()){
                System.out.println(m.getName());
            }

            DIDDoc didDoc = new DIDDoc(null, null, null, null, null);
            didDoc.
            didDocClass.getDeclaredField("DIDDocDecoder").setAccessible(true);
            // Obtener el objeto Companion de DIDDoc
            Object didDocCompanion = didDocClass.getField("DIDDocDecoder").get(null);

            // Obtener el método fromJson del objeto Companion
            Method fromJsonMethod = didDocCompanion.getClass().getMethod("fromJson", String.class);

            // Invocar el método fromJson y obtener el resultado
            DIDDoc decodedDoc = (DIDDoc) fromJsonMethod.invoke(didDocCompanion, response.getBody());

            System.out.println(decodedDoc);*/
            return Optional.of(decodedDoc);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return Optional.empty();
    }

/*
    private DIDDoc fromJson(String body, String did){

        DIDDocument didDocument = DIDDocument.fromJson(body);


        DIDDoc doc = new DIDDoc(null, null, null, null, null);
        DIDDocDecoder


        DIDDoc didDoc = new DIDDoc(
                did
                , verificationMethodToString(didDocument.getKeyAgreementVerificationMethods())
                , verificationMethodToString(didDocument.getAuthenticationVerificationMethods())
                , didDocument.getVerificationMethods(null)
                , null
        );
    }

    private List<String> verificationMethodToString(List<VerificationMethod> methods){
        List<String> l = new ArrayList<>();
        for(VerificationMethod v: methods){
            l.add(v.toJson());
        }
        return l;
    }

    private List<org.didcommx.didcomm.diddoc.VerificationMethod> toVerificationMethod(List<VerificationMethod> methods){
        List<org.didcommx.didcomm.diddoc.VerificationMethod> l = new ArrayList<>();
        for (VerificationMethod v: methods){
            String type = v.getType();
            VerificationMethodType verificationMethodType = VerificationMethodType.OTHER;
            if(v.isType("JsonWebKey2020")) verificationMethodType = VerificationMethodType.JSON_WEB_KEY_2020;
            if(v.isType("Ed25519VerificationKey2018")) verificationMethodType = VerificationMethodType.ED25519_VERIFICATION_KEY_2018;
            if(v.isType("Ed25519VerificationKey2020")) verificationMethodType = VerificationMethodType.ED25519_VERIFICATION_KEY_2020;
            if(v.isType("JsonWebKeys2020")) verificationMethodType = VerificationMethodType.JSON_WEB_KEY_2020;


            VerificationMaterialFormat.
            VerificationMaterial verificationMaterial = new VerificationMaterial();


            l.add(new org.didcommx.didcomm.diddoc.VerificationMethod(
                    v.getId().toString(),
                    verificationMethodType,
                    v.getController()))
        }
    }*/


    public DIDDocument resolveDID(String did) {
        if (!DIDParser.isValid(did, org.example.walletssi.model.DidMethod.EBSI)) {
            return null;
        }
        RestTemplate restTemplate = new RestTemplate();
        ResponseEntity<String> response = restTemplate.getForEntity(didRegistry + "/did?did=" + did, String.class);
        if (response == null || response.getBody() == null || response.getBody().isEmpty()) {
            return null;
        }

        System.out.println("\n\n\n\n" + response.getBody());

        DIDDocument didDocument = DIDDocument.fromJson(response.getBody());

        return didDocument;
    }
}
