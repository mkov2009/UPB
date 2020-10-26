package sk.FEI.Kovalak.Crypting;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class FileCryptRSA {

    public void encryptFromFileAndSave(String pathIn, PublicKey publicKey) throws IOException {
        System.out.println("File input: " + pathIn);
        String ext = "";
        if (pathIn.contains(".")) {
            ext = pathIn.substring(pathIn.lastIndexOf("."));
        }
        pathIn = pathIn.substring(0, pathIn.lastIndexOf("."));

        String pathOut = pathIn + "-enc" + ext;

        var fileInput = new File(pathIn + ext);
        var inputStream = new FileInputStream(fileInput);
        var inputBytes = new byte[(int) fileInput.length()];
        inputStream.read(inputBytes);

        try {
            var outputBytes = encrypt(inputBytes, publicKey);
            var fileEncryptOut = new File(pathOut);
            var outputStream = new FileOutputStream(fileEncryptOut);
            outputStream.write(outputBytes);
            outputStream.close();
        } catch (BadPaddingException | IllegalBlockSizeException | InvalidKeyException | NoSuchPaddingException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        inputStream.close();

        System.out.println("File successfully encrypted!");
        System.out.println("New File: " + pathOut);

    }

    public void decryptFromFileAndSave(String pathIn, PrivateKey privateKey) throws IOException {
        System.out.println("File input: " + pathIn);
        String ext = "";
        if (pathIn.contains(".")) {
            ext = pathIn.substring(pathIn.lastIndexOf("."));
        }
        pathIn = pathIn.substring(0, pathIn.lastIndexOf("."));

        String pathOut = pathIn + "-dec" + ext;
        var fileInput = new File(pathIn + ext);
        var inputStream = new FileInputStream(fileInput);
        var inputBytes = new byte[(int) fileInput.length()];
        inputStream.read(inputBytes);
        try {
            var outputBytes = decrypt(inputBytes, privateKey);
            var fileEncryptOut = new File(pathOut);
            var outputStream = new FileOutputStream(fileEncryptOut);
            outputStream.write(outputBytes);
            outputStream.close();
        } catch (BadPaddingException | IllegalBlockSizeException | InvalidKeyException | NoSuchPaddingException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        inputStream.close();

        System.out.println("File successfully encrypted!");
        System.out.println("New File: " + pathOut);


    }

    public static byte[] encrypt(byte[] data, String publicKey) throws BadPaddingException, IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, getPublicKey(publicKey));
        return cipher.doFinal(data);
    }
    public static byte[] encrypt(byte[] data, PublicKey publicKey) throws BadPaddingException, IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(data);
    }

    public static byte[] decrypt(byte[] data, PrivateKey privateKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(data);
    }

    public static String decrypt(String data, String base64PrivateKey) throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
        return new String(decrypt(Base64.getDecoder().decode(data.getBytes()), getPrivateKey(base64PrivateKey)));
    }


    public static PrivateKey getPrivateKey(String base64PrivateKey){
        PrivateKey privateKey = null;
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(base64PrivateKey.getBytes()));
        KeyFactory keyFactory = null;
        try {
            keyFactory = KeyFactory.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        try {
            privateKey = keyFactory.generatePrivate(keySpec);
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return privateKey;
    }

    public static PrivateKey getPrivateKey(byte[] bytePrivateKey){
        return getPrivateKey(Base64.getEncoder().encodeToString(bytePrivateKey));
    }

    //
    public static PublicKey getPublicKey(String base64PublicKey){
        PublicKey publicKey = null;
        try{
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(base64PublicKey.getBytes()));
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            publicKey = keyFactory.generatePublic(keySpec);
            return publicKey;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return publicKey;
    }


    public static PublicKey getPublicKey(byte[] bytePublicKey){
        return getPublicKey(Base64.getEncoder().encodeToString(bytePublicKey));
    }


    public static void writeToFile(String path, byte[] key) throws IOException {
        File f = new File(path);

        FileOutputStream fos = new FileOutputStream(f);
        fos.write(key);
        fos.flush();
        fos.close();
    }

    public static byte[] readFromFile(String path) throws IOException {

        var fileInput = new File(path);
        var inputStream = new FileInputStream(fileInput);
        var inputBytes = new byte[(int) fileInput.length()];
        inputStream.read(inputBytes);

        return inputBytes;
    }



}
