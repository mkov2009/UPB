//////////////////////////////////////////////////////////////////////////
// TODO:                                                                //
// Uloha1: Vytvorit funkciu na bezpecne generovanie saltu.              //
// Uloha2: Vytvorit funkciu na hashovanie.                              //
// Je vhodne vytvorit aj dalsie pomocne funkcie napr. na porovnavanie   //
// hesla ulozeneho v databaze so zadanym heslom.                        //
//////////////////////////////////////////////////////////////////////////
package sk.Kovalak;


import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Security {
    private  byte[] salt;

    public Security() {
        salt = generateSalt();
    }

    public Security(String salt){
        this.salt = Base64.getDecoder().decode(salt);
    }

    protected String hash(String password) throws Exception{
        /*
        *   Pred samotnym hashovanim si najskor musite ulozit instanciu hashovacieho algoritmu.
        *   Hash sa uklada ako bitovy retazec, takze ho nasledne treba skonvertovat na String (napr. cez BigInteger);
        */

        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 128);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        byte[] hashB = factory.generateSecret(spec).getEncoded();
        String hash = Base64.getEncoder().encodeToString(hashB);

        return hash;
    }

    protected static byte[] generateSalt(){
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        return salt;
    }
    
    protected String getSalt() {
        /*
        *   Salt treba generovat cez secure funkciu.
        */
        //long salt = 0;

        return Base64.getEncoder().encodeToString(salt);
    }

    public void setSalt(String salt) {

        this.salt = Base64.getDecoder().decode(salt);
    }

    public static boolean passwordValidation(String password) {
        String regEx = "^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.{6,})"; //male alebo velke pismeno, cislo a 6 znakov
        CharSequence inputStr = password;

        Pattern pattern = Pattern.compile(regEx,Pattern.CASE_INSENSITIVE);
        Matcher matcher = pattern.matcher(inputStr);

        if(matcher.find())
            return true;
        else
            return false;
    }
}

