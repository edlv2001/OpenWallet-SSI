package org.example.walletssi.model.vc;

import com.danubetech.verifiablecredentials.VerifiableCredential;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.github.fge.jsonschema.core.report.ProcessingMessage;
import com.github.fge.jsonschema.core.report.ProcessingReport;
import com.github.fge.jsonschema.main.JsonSchema;
import com.github.fge.jsonschema.main.JsonSchemaFactory;
import foundation.identity.jsonld.JsonLDObject;
import org.didcommx.didcomm.diddoc.DIDDoc;
import org.didcommx.didcomm.diddoc.DIDDocResolver;
import org.didcommx.didcomm.diddoc.VerificationMethod;
import org.example.walletssi.model.DidMethod;
import org.example.walletssi.model.didUtils.DIDParser;
import org.example.walletssi.model.handlers.config.DidMethodHandlerConfig;
import org.example.walletssi.model.vc.signature.VerifySignature;
import org.springframework.web.client.RestTemplate;

import java.io.InputStream;
import java.io.StringReader;
import java.net.URI;
import java.util.Iterator;
import java.util.Map;

public class VerifiableCredentialVerifier {

    public boolean verify(String vc, DidMethodHandlerConfig config, boolean fromTrustedRegistry){
        VerifiableCredential credential = VerifiableCredential.fromJson(vc);
        return verify(credential, config, fromTrustedRegistry);
    }

    public boolean verify(VerifiableCredential vc, DidMethodHandlerConfig config, boolean fromTrustedRegistry){
        String schemaRegistry = (DidMethod.getHandler(DIDParser.parseDID(vc.getIssuer().toString()), config)).getSchemaRegistry();
        if(!validateSchema(schemaRegistry, vc, fromTrustedRegistry))
            return false;
        return verifyWithoutRegistry(vc, config);
    }

    public boolean verifyWithoutRegistry(String vc, DidMethodHandlerConfig config){
        VerifiableCredential credential = VerifiableCredential.fromJson(vc);
        return verifyWithoutRegistry(credential, config);
    }


    public boolean verifyWithoutRegistry(VerifiableCredential credential, DidMethodHandlerConfig config){
        String didIssuer = credential.getIssuer().toString();
        DidMethod didMethod = DIDParser.parseDID(didIssuer);

        DIDDocResolver resolver = DidMethod.getResolver(didMethod, config);

        DIDDoc doc = resolver.resolve(didIssuer).orElse(null);
        if(doc == null)
            return false;

        for(VerificationMethod v: doc.getVerificationMethods()){
            if(VerifySignature.tryVerify(v, credential))
                return true;
        }
        return false;
    }

    protected static boolean validateSchema(String registry, JsonLDObject json, boolean fromTrustedRegistry){
        if(registry == null && fromTrustedRegistry) //Si se requiere que se pida del registro y no existe
            return false;
        URI schemaId = getCredentialSchemaId(json);
        if(schemaId == null) //Si la credencial no tiene schema
            return false;

        if(fromTrustedRegistry && !schemaId.toString().startsWith(registry))
            return false;

        RestTemplate restTemplate = new RestTemplate();
        String schema = restTemplate.getForObject(schemaId, String.class);

        return validateJSONSchema(json.toJson(), schema);
    }


    protected static boolean validateJSONSchema (String json, String schema){


        ObjectMapper objectMapper = new ObjectMapper();
        JsonSchemaFactory schemaFactory = JsonSchemaFactory.byDefault();
        try {
            JsonNode jsonNode = objectMapper.readTree(json);
            JsonNode schemaNode = objectMapper.readTree(schema);
            JsonSchema schemaJson = schemaFactory.getJsonSchema(schemaNode);
            ProcessingReport report = schemaJson.validate(jsonNode);
            return report.isSuccess();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }


    }

    private static URI getCredentialSchemaId(JsonLDObject json){
        try {
            Map<String, Object> credentialSchema = (Map<String, Object>) json.getJsonObject().get("credentialSchema");
            return URI.create((String) credentialSchema.get("id"));
        } catch (Exception e){
            return null;
        }

        //return json.getJsonObject().get("credentialSchema.id").toString();
    }

}
