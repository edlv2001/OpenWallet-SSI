package es.edu.walletssi.model.handlers;

import foundation.identity.did.DIDDocument;
import org.didcommx.didcomm.diddoc.DIDDocResolver;

import java.io.File;
import java.io.FileNotFoundException;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.List;
import java.util.Scanner;
import java.util.function.Predicate;

public interface DidMethodHandler {
    public String genDID(PublicKey publicKey);
    public String getDIDMethod();
    public File getDir();
    public DIDDocResolver getResolver();

    public String getDIDRegistry();

    public Class<?> getConfigClass();

    public String getSchemaRegistry();

    default List<String> listDids(){
        Predicate<String> isDID = (did) -> did.matches("did%3" + getDIDMethod() + "%3.*?");
        //Predicate<String> isDID = (did) -> true;
        List<String> list = Arrays.stream(getDir().listFiles())
                .toList()
                .stream()
                .map(File::getName)
                .filter(isDID)
                .map((String s) -> {s = s.replace("%3", ":"); return s; })
                .toList();
        return list;
    }

    default boolean isDID(File f){
        Predicate<String> isDID = (did) -> did.matches("did%3" + getDIDMethod() + "%3.*?");
        return isDID.test(f.getName());
        //return f.getName().matches("did%3" + getDIDMethod() + "%3*" );
    }

    default String getDidDocFromFile(String did){
        did = did.replaceFirst(":", "%3");
        did = did.replaceFirst(":", "%3");
        File f = new File(getDir(), did);
        if(!f.exists()){
            throw new IllegalArgumentException("DID has not been created");
        }
        try {
            Scanner sc = new Scanner(f);
            StringBuilder stringBuilder = new StringBuilder();
            while(sc.hasNext()){
                stringBuilder.append(sc.nextLine());
                if(sc.hasNext())
                    stringBuilder.append("\n");
            }
            String res = stringBuilder.toString();
            DIDDocument.fromJson(res);
            return res;

        } catch (FileNotFoundException e) {
            return null;
        }
    }

    public void storeDID(String did, String didDoc);

}
