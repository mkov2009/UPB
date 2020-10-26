package sk.FEI.Kovalak.Crypting;

import java.io.IOException;
import java.security.*;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;


public class FileCryptMain {

    public static void master (String[] args) throws NoSuchPaddingException, NoSuchAlgorithmException, IOException, BadPaddingException, IllegalBlockSizeException, InvalidKeyException, InvalidAlgorithmParameterException {
        //initialization
        //Key generation
        KeyController keyController = new KeyController();
        keyController.generateKey();
        keyController.RSAKeyPairGenerator();

        boolean encrypt = false;
        boolean decrypt = false;

        String path = "";
        String privateKeyPath="";

        // examine all the command line arguments
        for (int i = 0; i < args.length; i++) {
            if (args[i].equals("-encrypt")) {
                encrypt = true;
            } else if (args[i].equals("-decrypt")) {
                decrypt = true;
            } else if (args[i].equals("-path")) {
                path = args[++i];
            } else if(args[i].equals("-pk")){
                privateKeyPath = args[++i];
            }
        }

        //Argument validation
        if (encrypt == decrypt) {
            if (encrypt) {
                System.err.println("Cannot encrypt and decrypt file!");
            } else {
                System.err.println("Must specify -encrypt or - decrypt.");
                System.exit(1);
            }
        }
        if (path.equals("")) {
            System.err.println("Missing path to file.");
            System.exit(1);
        }

        System.out.println("File input: " + path);
        String ext = "";
        if (path.contains(".")) {
            ext = path.substring(path.lastIndexOf("."));
        }
        path = path.substring(0, path.lastIndexOf("."));
        long startTime = System.currentTimeMillis();
        if (encrypt) {

            FileCrypt.encryptedFile(keyController, path, ext);

        }
        if (decrypt) {
            if(privateKeyPath.equals("")){
                System.err.println("Missing path to stored Private key.");
            }
            FileCrypt.decryptedFile(path + ext, path + ext, privateKeyPath);
        }
        long endTime = System.currentTimeMillis();
        System.out.println("That took " + (endTime - startTime) + " milliseconds.");

    }
}
