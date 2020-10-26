package sk.FEI.Kovalak.Crypting;

import javax.crypto.KeyGenerator;
import java.security.*;

public class KeyController {
    private PrivateKey privateKey;
    private PublicKey publicKey;
    private Key symmetricKey;

    public void generateKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        symmetricKey = keyGen.generateKey();
    }

    public void RSAKeyPairGenerator() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair pair = keyGen.generateKeyPair();
        privateKey = pair.getPrivate();
        publicKey = pair.getPublic();
    }



    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public Key getSymmetricKey() {
        return symmetricKey;
    }
}
