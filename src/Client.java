import javax.crypto.*;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Scanner;


/**
 * The type Client.
 */
public class Client {

    private static ObjectInputStream ins;

    private static ObjectOutputStream outs;

    private static Key cleDES;

    private static String localhote="localhost";

    /**
     * Instantiates a new Client.
     */
    public Client() {
    }


    /**
     * main qui lance l'application client, en initialisant la connexion vers le serveur, génère la clé DES discute avec le serveur
     *
     * @param args the input arguments
     * @throws IOException               the io exception
     * @throws NoSuchPaddingException    the no such padding exception
     * @throws NoSuchAlgorithmException  the no such algorithm exception
     * @throws IllegalBlockSizeException the illegal block size exception
     * @throws BadPaddingException       the bad padding exception
     * @throws InvalidKeyException       the invalid key exception
     * @throws ClassNotFoundException    the class not found exception
     */
    public static void main(String[] args) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, ClassNotFoundException {

        Scanner sc = new Scanner(System.in);
        Socket s = new Socket(localhote,2222);
        ins = new ObjectInputStream(s.getInputStream());
        outs = new ObjectOutputStream(s.getOutputStream());

        //méthode qui génère la clé DES, reçoi la clé publique, chiffre la clé DES (voir plus bas)
        createKeyDES();

        while(true) {

            System.out.println("\nVeuillez saisir votre message");
            String str = sc.nextLine();

            // chiffre le message
            byte[] reponseEncoded = EncodeDecode.encondedInDES(str.getBytes(),cleDES);
            // on envoit d'abord la longueur du tableau de byte
            outs.write(reponseEncoded.length);
            // on envoit ensuite le contenu du tableau
            outs.write(reponseEncoded);
            outs.flush();

            if(str.equals("stop")) { break;}

            System.out.println("Message envoyé");

            System.out.println("\nAttente Réponse Serveur...");

            // lis la réponse du serveur, d'abord la longueur du tableau
            int tailleMessage= ins.read();
            // lis le contenu du tableau
            byte[] messageEncoded = ins.readNBytes(tailleMessage);

            // dechiffre le message recu
            byte[] messageDecode = EncodeDecode.decodedInDes(messageEncoded,cleDES);
            //Afffiche le message recu
            String md  = new String(messageDecode, StandardCharsets.UTF_8);
            System.out.println( "message Recu : " +md);

            if(md.equals("stop")) { break;}
        }
        ins.close();
        outs.close();
        s.close();
        System.out.println("Fin de la conversation");

    }

    /**
     * génère la clé DES, reçoit la clé publique, chiffre les DES et l'envoie.
     *
     * @throws IOException               the io exception
     * @throws NoSuchAlgorithmException  the no such algorithm exception
     * @throws ClassNotFoundException    the class not found exception
     * @throws NoSuchPaddingException    the no such padding exception
     * @throws InvalidKeyException       the invalid key exception
     * @throws BadPaddingException       the bad padding exception
     * @throws IllegalBlockSizeException the illegal block size exception
     */
    public static void createKeyDES() throws IOException, NoSuchAlgorithmException, ClassNotFoundException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

        // client génère la clé DES
        KeyGenerator keyGen = KeyGenerator.getInstance("DES");
        keyGen.init(56); // 56 = valeur imposée
        cleDES = keyGen.generateKey();

        // il reçoit la clé publique
        PublicKey publicKey = (PublicKey) ins.readObject();

        // il chiffre la clé DES et l'envoie au serveur
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] keyDESEncoded = cipher.doFinal(cleDES.getEncoded());
        outs.write(keyDESEncoded);
        outs.flush();

    }
}