import es.edu.walletssi.Wallet;
import es.edu.walletssi.init.WalletConfiguration;
import es.edu.walletssi.key.KeyType;
import es.edu.walletssi.key.exception.IncorrectPasswordException;
import es.edu.walletssi.model.DidMethod;
import es.edu.walletssi.model.handlers.config.EBSIMethodHandlerConfig;

import java.net.URI;
import java.security.KeyPair;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class IssuerPolice implements Issuer{

    private Wallet wallet;

    private String name;

    private String did;

    private KeyPair kp;

    public IssuerPolice(String name, String globalPath){
        this.name = name;
        WalletConfiguration configuration = new WalletConfiguration(
                DidMethod.EBSI,
                new EBSIMethodHandlerConfig(globalPath + "/dids", null, null),
                globalPath + "/keys",
                globalPath + "/vcOwned",
                globalPath + "/vcStore",
                globalPath + "/vpStore"
        );
        wallet = new Wallet(configuration);
        try{
            kp = wallet.getKeys("key1", "1234", KeyType.ED25519);
            if(kp == null){
                wallet.genKey("key1","1234", KeyType.ED25519);
                kp = wallet.getKeys("key1", "1234", KeyType.ED25519);
            }
        } catch (IncorrectPasswordException e){
            throw new RuntimeException("Clave ya existente y con otra contraseña");
        }
        List<String> l = wallet.listDIDs();
        if(l.size()> 0){
            did = l.get(0);
        }
        else {
            did = wallet.genDID(kp.getPublic());
        }
        System.out.println("El issuer " + name + " ha generado el DID \""  + did + "\".");
    }

    private String issueID(String didHolder){
        Map<String, Object> claims = new HashMap<>();
        claims.put("name", getName());
        claims.put("familyName", getFamiliyName());
        return wallet.issueVC(URI.create("https://schema.affinidi.com/IDReducedV1-0.json"), "VerifiableID",claims, did, kp, didHolder, Date.from(Instant.now().plusSeconds(7200)), false);
    }

    private boolean validateJWTMockUP(String jwt){ return true; }

    private String getName(){
        String[] nameList = {"Daniel", "David", "Gabriel", "Benjamín", "Samuel", "Lucas", "Ángel", "José", "Adrián", "Sebastián", "Xavier", "Juan", "Luis", "Diego", "Óliver", "Carlos", "Jesús", "Alex", "Max", "Alejandro", "Antonio", "Miguel", "Víctor", "Joel", "Santiago", "Elías", "Iván", "Óscar", "Leonardo", "Eduardo", "Alan", "Nicolás", "Jorge", "Omar", "Paúl", "Andrés", "Julián", "Josué", "Román", "Fernando", "Javier", "Abraham", "Ricardo", "Francisco", "César", "Mario", "Manuel", "Édgar", "Alexis", "Israel", "Mateo", "Héctor", "Sergio", "Emiliano", "Simón", "Rafael", "Martín", "Marco", "Roberto", "Pedro", "Emanuel", "Abel", "Rubén", "Fabián", "Emilio", "Joaquín", "Marcos", "Lorenzo", "Armando", "Adán", "Raúl", "Julio", "Enrique", "Gerardo", "Pablo", "Jaime", "Saúl", "Esteban", "Rodrigo", "Arturo", "Mauricio", "Orlando", "Hugo", "Salvador", "Alfredo", "Maximiliano", "Ramón", "Ernesto", "Tobías", "Abram", "Noé", "Guillermo", "Ezequiel", "Lucián", "Alonzo", "Felipe", "Matías", "Tomás", "Jairo", "Isabella", "Olivia", "Sofía", "Victoria", "Amelia", "Alexa", "Julia", "Camila", "Alexandra", "Maya", "Andrea", "Ariana", "María", "Eva", "Angelina", "Valeria", "Natalia", "Isabel", "Sara", "Liliana", "Adriana", "Juliana", "Gabriela", "Daniela", "Valentina", "Lila", "Vivian", "Nora", "Ángela", "Elena", "Clara", "Eliana", "Alana", "Miranda", "Amanda", "Diana", "Ana", "Penélope", "Aurora", "Alexandría", "Lola", "Alicia", "Amaya", "Alexia", "Jazmín", "Mariana", "Alina", "Lucía", "Fátima", "Ximena", "Laura", "Cecilia", "Alejandra", "Esmeralda", "Verónica", "Daniella", "Miriam", "Carmen", "Iris", "Guadalupe", "Selena", "Fernanda", "Angélica", "Emilia", "Lía", "Tatiana", "Mónica", "Carolina", "Jimena", "Dulce", "Talía", "Estrella", "Brenda", "Lilian", "Paola", "Serena", "Celeste", "Viviana", "Elisa", "Melina", "Gloria", "Claudia", "Sandra", "Marisol", "Asia", "Ada", "Rosa", "Isabela", "Regina", "Elsa", "Perla", "Raquel", "Virginia", "Patricia", "Linda", "Marina", "Leila", "América", "Mercedes"};
        return nameList[(int)(Math.random()* nameList.length)];

    }

    private String getFamiliyName(){
        String[] familyNameList = {"Garcia", "Rodriguez", "Gonzalez", "Fernandez", "Lopez", "Martinez", "Sanchez", "Perez", "Gomez", "Martin", "Jimenez", "Hernandez", "Ruiz", "Diaz", "Moreno", "Muñoz", "Alvarez", "Romero", "Gutierrez", "Alonso", "Navarro", "Torres", "Dominguez", "Ramos", "Vazquez", "Ramirez", "Gil", "Serrano", "Morales", "Molina", "Blanco", "Suarez", "Castro", "Ortega", "Delgado", "Ortiz", "Marin", "Rubio", "Nuñez", "Medina", "Sanz", "Castillo", "Iglesias", "Cortes", "Garrido", "Santos", "Guerrero", "Lozano", "Cano", "Cruz", "Mendez", "Flores", "Prieto", "Herrera", "Peña", "Leon", "Marquez", "Cabrera", "Gallego", "Calvo", "Vidal", "Campos", "Reyes", "Vega", "Fuentes", "Carrasco", "Diez", "Aguilar", "Caballero", "Nieto", "Santana", "Vargas", "Pascual", "Gimenez", "Herrero", "Hidalgo", "Montero", "Lorenzo", "Santiago", "Benitez", "Duran", "Ibañez", "Arias", "Mora", "Ferrer", "Carmona", "Vicente", "Rojas", "Soto", "Crespo", "Roman", "Pastor", "Velasco", "Parra", "Saez", "Moya", "Bravo", "Rivera", "Gallardo", "Soler"};
        return familyNameList[(int)(Math.random()* familyNameList.length)];
    }


    public String giveVC(URI schema, String did, String mockUpJWT){
        //LOGIN
        if(!validateJWTMockUP(mockUpJWT)) return null;
        //ISSUANCE FROM AVAILABLE SCHEMAS
        if(schema.toString().equals("https://schema.affinidi.com/IDReducedV1-0.json"))
            return issueID(did);
        return null;
    }

}
