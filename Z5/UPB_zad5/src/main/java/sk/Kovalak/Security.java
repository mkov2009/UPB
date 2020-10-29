//////////////////////////////////////////////////////////////////////////
// TODO:                                                                //
// Uloha1: Vytvorit funkciu na bezpecne generovanie saltu.              //
// Uloha2: Vytvorit funkciu na hashovanie.                              //
// Je vhodne vytvorit aj dalsie pomocne funkcie napr. na porovnavanie   //
// hesla ulozeneho v databaze so zadanym heslom.                        //
//////////////////////////////////////////////////////////////////////////
package sk.Kovalak;

import org.passay.*;

import org.passay.dictionary.WordListDictionary;
import org.passay.dictionary.WordLists;
import org.passay.dictionary.sort.ArraysSort;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.*;
import java.net.URISyntaxException;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;


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

    public boolean passwordValidation(String password) throws IOException, URISyntaxException {

        List<Rule> rules = new ArrayList<>();

        //Pravidlo 1: 8 az 16 znakov.
        rules.add(new LengthRule(6, 32));
        //Pravidlo 2: Ziadna medzera.
        rules.add(new WhitespaceRule());
        //Pravidlo 3a: 1 velke pismeno.
        rules.add(new CharacterRule(EnglishCharacterData.UpperCase, 1));
        //Pravidlo 3b: 1 male pismeno.
        rules.add(new CharacterRule(EnglishCharacterData.LowerCase, 1));
        //Pravidlo 3c: 1 cislo.
        rules.add(new CharacterRule(EnglishCharacterData.Digit, 1));

        InputStream inputStream = getClass().getResourceAsStream("/most-common-passwords.txt");

        DictionaryRule rule = new DictionaryRule(
                new WordListDictionary(WordLists.createFromReader(
                        new BufferedReader[] {new BufferedReader(new InputStreamReader(inputStream))},
                        false,
                        new ArraysSort()
                ))
        );
        rules.add(rule);
        PasswordValidator passwordValidator = new PasswordValidator(rules);
        PasswordData passwordData = new PasswordData(password);
        RuleResult result = passwordValidator.validate(passwordData);
        return result.isValid();

    }
}

