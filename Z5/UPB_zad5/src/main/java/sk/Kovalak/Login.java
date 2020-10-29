//////////////////////////////////////////////////////////////////////////
// TODO:                                                                //
// Uloha2: Upravte funkciu na prihlasovanie tak, aby porovnavala        //
//         heslo ulozene v databaze s heslom od uzivatela po            //
//         potrebnych upravach.                                         //
// Uloha3: Vlozte do prihlasovania nejaku formu oneskorenia.            //
//////////////////////////////////////////////////////////////////////////
package sk.Kovalak;

import java.io.IOException;
import java.util.StringTokenizer;
import sk.Kovalak.Database.MyResult;

public class Login {
    protected static MyResult prihlasovanie(String meno, String heslo) throws IOException, Exception{

        Thread.sleep(500);  // oneskorenie 0.5 sekundy

        MyResult account = Database.find("hesla.txt", meno);
        if (!account.getFirst()){
            return new MyResult(false, "Nespravne meno.");
        }
        else {
            StringTokenizer st = new StringTokenizer(account.getSecond(), ":");
            st.nextToken();      //meno

            //ulozenie si hashovaneho hesla z databazy a salt-u
            String hashedPassword = st.nextToken(); //heslo z databazy
            String salt = st.nextToken(); //salt z databazy
            Security security = new Security(salt);

            boolean rightPassword = hashedPassword.equals(security.hash(heslo));
            if (!rightPassword)    
                return new MyResult(false, "Nespravne heslo.");
        }
        return new MyResult(true, "Uspesne prihlasenie.");
    }
}
