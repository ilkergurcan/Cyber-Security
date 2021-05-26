import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import org.testng.annotations.Test;
public class DES {
    @Test
    public static void main(String[] args) {
        try{
            KeyGenerator kg = KeyGenerator.getInstance("DES");
            SecretKey myDESKey = kg.generateKey();
            System.out.println("KEY: " + myDESKey);

            Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, myDESKey);

            byte[] text = "ilker gürcan".getBytes();
            System.out.println("Text in bytes: " + text);
            System.out.println("Original Text: " + new String(text));

            byte[] TextEnc = cipher.doFinal(text);
            System.out.println("Encrypted Text: "+ new String(TextEnc, StandardCharsets.UTF_8));

            cipher.init(Cipher.DECRYPT_MODE, myDESKey);
            byte[] TextDec = cipher.doFinal(TextEnc);
            System.out.println("Decrypted Text: " + new String(TextDec));

        }catch(Exception e){
            System.out.println(e);
        }
    }
    }
