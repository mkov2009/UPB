package sk.FEI.Kovalak.Crypting;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import at.favre.lib.crypto.HKDF;

public class FileCrypt {

    public static void encryptedFile(KeyController keyController, String path, String ext) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IOException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {

        String fileInputPath = path + ext;
        String fileOutPath = path + "-enc" + ext;

        Key key = keyController.getSymmetricKey();
        SecureRandom secureRandom = new SecureRandom();
        byte[] iv = new byte[16];
        secureRandom.nextBytes(iv);

        //Encrypt Symmetric key with RSA encryption and save Private key to file.
        byte[] enKey = FileCryptRSA.encrypt(key.getEncoded(),keyController.getPublicKey());
        FileCryptRSA.writeToFile(path+".pk", keyController.getPrivateKey().getEncoded());

        //Split key to 2 parts. One for encryption and the second for authentication
        byte[] encKey = HKDF.fromHmacSha256().expand(key.getEncoded(), "encKey".getBytes(StandardCharsets.UTF_8), 16);
        byte[] authKey = HKDF.fromHmacSha256().expand(key.getEncoded(), "authKey".getBytes(StandardCharsets.UTF_8), 32); //key is 32 byte

        var cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(encKey, "AES"), new IvParameterSpec(iv));

        var fileInput = new File(fileInputPath);
        var inputStream = new FileInputStream(fileInput);
        var inputBytes = new byte[(int) fileInput.length()];
        inputStream.read(inputBytes);

        byte[] cipherText = cipher.doFinal(inputBytes);

        SecretKey macKey = new SecretKeySpec(authKey, "HmacSHA256");
        Mac hmac = Mac.getInstance("HmacSHA256");
        hmac.init(macKey);
        hmac.update(iv);
        hmac.update(enKey);
        hmac.update(cipherText);


        byte[] mac = hmac.doFinal();

        ByteBuffer byteBuffer = ByteBuffer.allocate(1 + iv.length + 1 + enKey.length + 1 + mac.length + cipherText.length);
        byteBuffer.put((byte) iv.length);
        byteBuffer.put(iv);
        byteBuffer.put((byte) enKey.length);
        byteBuffer.put(enKey);
        byteBuffer.put((byte) mac.length);
        byteBuffer.put(mac);
        byteBuffer.put(cipherText);
        byte[] cipherMessage = byteBuffer.array();

        var fileEncryptOut = new File(fileOutPath);
        var outputStream = new FileOutputStream(fileEncryptOut);
        outputStream.write(cipherMessage);

        inputStream.close();
        outputStream.close();

        System.out.println("File successfully encrypted!");
        System.out.println("New File: " + fileOutPath);
    }

    public static void decryptedFile(String fileInputPath, String fileOutPath, String privateKeyPath) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IOException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        fileOutPath = fileOutPath.replace("-enc","-dec");

        var fileInput = new File(fileInputPath);
        var inputStream = new FileInputStream(fileInput);
        var inputBytes = new byte[(int) fileInput.length()];
        inputStream.read(inputBytes);

        ByteBuffer byteBuffer = ByteBuffer.wrap(inputBytes);

        int ivLength = (byteBuffer.get());
        if (ivLength != 16) { // check input parameter
            throw new IllegalArgumentException("File corrupted.");
        }

        byte[] iv = new byte[ivLength];
        byteBuffer.get(iv);

        int enKeyLength = (byteBuffer.get());
        if(enKeyLength != 0){
            throw new IllegalArgumentException("File corrupted.");
        }
        byte[] enKey = new byte[enKeyLength+256];
        byteBuffer.get(enKey);

        //Decryption of a Symmetric key
        byte[] privateKey = FileCryptRSA.readFromFile(privateKeyPath);
        byte[] decryptedKey = FileCryptRSA.decrypt(enKey,FileCryptRSA.getPrivateKey(privateKey));
        Key key = new SecretKeySpec(decryptedKey, 0, decryptedKey.length, "AES");

        int macLength = (byteBuffer.get());
        if (macLength != 32) { // check input parameter
            throw new IllegalArgumentException("File corrupted.");
        }

        byte[] mac = new byte[macLength];
        byteBuffer.get(mac);

        byte[] cipherText = new byte[byteBuffer.remaining()];
        byteBuffer.get(cipherText);


        byte[] encKey = HKDF.fromHmacSha256().expand(key.getEncoded(), "encKey".getBytes(StandardCharsets.UTF_8), 16);
        byte[] authKey = HKDF.fromHmacSha256().expand(key.getEncoded(), "authKey".getBytes(StandardCharsets.UTF_8), 32);


        SecretKey macKey = new SecretKeySpec(authKey, "HmacSHA256");
        Mac hmac = Mac.getInstance("HmacSHA256");
        hmac.init(macKey);
        hmac.update(iv);
        hmac.update(enKey);
        hmac.update(cipherText);

        byte[] refMac = hmac.doFinal();

        if (!MessageDigest.isEqual(refMac, mac)) {
            throw new SecurityException("File corrupted.");
        }

        final Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(encKey, "AES"), new IvParameterSpec(iv));
        byte[] outputBytes = cipher.doFinal(cipherText);

        var fileEncryptOut = new File(fileOutPath);
        var outputStream = new FileOutputStream(fileEncryptOut);
        outputStream.write(outputBytes);

        inputStream.close();
        outputStream.close();

        System.out.println("File successfully decrypted!");
        System.out.println("New File: " + fileOutPath);
    }
}
