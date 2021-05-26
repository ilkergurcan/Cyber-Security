import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.util.Base64;
//System.out.println(encryptedData);

import org.testng.annotations.Test;

public class Blowfish {
    private static final String UNICODE_FORMAT = "UTF-8";

    public static void main(String[] args) {

        String text = "ilker gürcan";
        try{
            SecretKey key = generateKey("Blowfish");
            Cipher cipher;
            cipher = Cipher.getInstance("Blowfish");

            System.out.println("Original Text: " + text);

            byte[]  encryptedData = encryptString(text,key,cipher);
            String encryptedString = new String(encryptedData,StandardCharsets.UTF_8);
            System.out.println("Encrypted Text: " + encryptedString);

            String decrypted = decryptString(encryptedData,key,cipher);
            System.out.println("Decrypted Text: " + decrypted);



        }catch(Exception e){

        }
    }

    public static SecretKey generateKey(String encryptionType){
        try
        {
            KeyGenerator keyGenerator = KeyGenerator.getInstance(encryptionType);
           // keyGenerator.init(256);
            SecretKey myKey = keyGenerator.generateKey();
            return myKey;
        }catch(Exception e)
        {
            return null;
        }
    }

    public static byte[] encryptString(String dataToEncrypt, SecretKey myKey, Cipher cipher){
        try
        {
            byte[] text = dataToEncrypt.getBytes(UNICODE_FORMAT);
            cipher.init(Cipher.ENCRYPT_MODE, myKey);
            byte[] textEncrypted = cipher.doFinal(text);
            return textEncrypted;
        }catch(Exception e)
        {
            return null;
        }
    }

    public static String decryptString(byte[] dataToDecrypt, SecretKey myKey, Cipher cipher){
        try
        {
            cipher.init(Cipher.DECRYPT_MODE,myKey);
            byte[] textDecrypted = cipher.doFinal(dataToDecrypt);
            String result = new String(textDecrypted);
            return result;
        }catch (Exception e)
        {
            System.out.println(e);
            return null;
        }
    }

}
