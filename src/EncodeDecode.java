import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;

public class EncodeDecode {




    /**
     * Encode le message avec la clé DES et renvoie le mesage encodé.
     *
     * @param dataToEncode le message à encodé
     * @return  byte [ ] le message encodé
     * @throws NoSuchPaddingException    the no such padding exception
     * @throws NoSuchAlgorithmException  the no such algorithm exception
     * @throws InvalidKeyException       the invalid key exception
     * @throws BadPaddingException       the bad padding exception
     * @throws IllegalBlockSizeException the illegal block size exception
     */
    public static byte[] encondedInDES(byte[] dataToEncode,Key cleDES) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        //On reçoit le tableau de byte[]du message, on utilise ensuite la clé DES pour l'encrypter
        Cipher cipher = Cipher.getInstance("DES");
        cipher.init(Cipher.ENCRYPT_MODE, cleDES);
        byte[] dataEncoded = cipher.doFinal(dataToEncode);
        return dataEncoded;
    }

    /**
     * Decode le message passé en paramètre avec la clé DES et le renvoie décodé.
     *
     * @param dataToDecode les données à décodé
     * @return  byte [ ] le message décodé
     * @throws NoSuchPaddingException    the no such padding exception
     * @throws NoSuchAlgorithmException  the no such algorithm exception
     * @throws InvalidKeyException       the invalid key exception
     * @throws BadPaddingException       the bad padding exception
     * @throws IllegalBlockSizeException the illegal block size exception
     */
    public static byte[] decodedInDes(byte[] dataToDecode,Key cleDES) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        //On reçoit le tableau de byte[] encrypter, on utilise ensuite la clé DES pour le décrypter
        Cipher cipher = Cipher.getInstance("DES");
        cipher.init(Cipher.DECRYPT_MODE, cleDES);
        byte[] dataDecoded = cipher.doFinal(dataToDecode);
        return dataDecoded;
    }


}
