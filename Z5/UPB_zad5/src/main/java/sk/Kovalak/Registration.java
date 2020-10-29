//////////////////////////////////////////////////////////////////////////
// TODO:                                                                //
// Uloha1: Do suboru s heslami ulozit aj salt.                           //
// Uloha2: Pouzit vytvorenu funkciu na hashovanie a ulozit heslo        //
//         v zahashovanom tvare.                                        //
//////////////////////////////////////////////////////////////////////////
package sk.Kovalak;

import java.security.NoSuchAlgorithmException;
import sk.Kovalak.Database.MyResult;


public class Registration {
    protected static MyResult registracia(String meno, String heslo, String salt) throws NoSuchAlgorithmException, Exception{
        if (Database.exist("hesla.txt", meno)){
            System.out.println("Meno je uz zabrate.");
            return new MyResult(false, "Meno je uz zabrate.");
        }
        else {
            /*
            *   Salt sa obvykle uklada ako tretia polozka v tvare [meno]:[heslo]:[salt].
            */
            Database.add("hesla.txt", meno + ":" + heslo + ":" + salt);
        }
        return new MyResult(true, "");
    }
    
}
