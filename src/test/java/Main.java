import java.io.File;

public class Main {
    public static void main(String[] args) {
        IssuerBank issuer = new IssuerBank("Banco Santander", "issuer/santander");
        Holder holder = new Holder("Eduardo", "holder/eduardo");
        Verifier verifier = new Verifier("MediaMarkt", "verifier/mediamarkt");
        IssuerPolice police = new IssuerPolice("CNP", "issuer/cnp");

        holder.askForID(issuer);
        holder.askForCreditScore(issuer);
        verifier.askForVC(holder);







    }

}
