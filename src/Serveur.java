import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.*;
import java.lang.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Scanner;

/**
 * The type Serveur.
 */
public class Serveur {

    private static ObjectInputStream ins;

    private static ObjectOutputStream outs;

    private static Key cleDES;

    /**
     * main qui lance l'application, en lançant le socket et en attendant des connexion clients
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

        ServerSocket s = new ServerSocket(2222);
        System.out.println("Attente connexion");
        Socket soc = s.accept();
        System.out.println("Client connecte");

        outs = new ObjectOutputStream(soc.getOutputStream());
        ins = new ObjectInputStream(soc.getInputStream());

        //méthode qui génère le couple de clé, récupère la clé DES chiffrée et la déchiffre
        //voir plus bas pour détail
        generateSendRSA();

        while (true) {

            System.out.println("\nAttente Réponse Client...");

            int tailleMessage= ins.read();
            byte[] messageEncoded = ins.readNBytes(tailleMessage);

            // dechiffre le message recu
            byte[] messageDecode = EncodeDecode.decodedInDes(messageEncoded,cleDES);
            String md  = new String(messageDecode, StandardCharsets.UTF_8);

            if (md.equals("stop")) {
               break;
            }

            System.out.println( "message Recu : " +md);

            System.out.println("\nVeuillez saisir votre message");
            String str = sc.nextLine();

            // chiffre le message à envoyer
            byte[] reponseEncoded = EncodeDecode.encondedInDES(str.getBytes(),cleDES);

            //envoi le message encode au serveur, avec d'abord la taille du tableau
            outs.write(reponseEncoded.length);
            //envoi le contenu du tableau
            outs.write(reponseEncoded);
            outs.flush();
            System.out.println("Message envoyé");

            if (str.equals("stop")) {
              break;
            }
        }

        ins.close();
        outs.close();
        soc.close();
        System.out.println("Fin de la conversation");
    }


    /**
     * Génère et envoi la clé rsa, récupère la  clé DES, décode la clé DES.
     *
     * @throws IOException               the io exception
     * @throws ClassNotFoundException    the class not found exception
     * @throws NoSuchPaddingException    the no such padding exception
     * @throws InvalidKeyException       the invalid key exception
     * @throws BadPaddingException       the bad padding exception
     * @throws IllegalBlockSizeException the illegal block size exception
     * @throws NoSuchAlgorithmException  the no such algorithm exception
     */
    public static void generateSendRSA() throws IOException, ClassNotFoundException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException {
        // le serveur génère la paire de clé publique/privée
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(1024);
        KeyPair keyPair = keyPairGenerator.genKeyPair();
        PublicKey clePublic = keyPair.getPublic();
        PrivateKey clePrivate = keyPair.getPrivate();

        // le serveur envoie la clé publique
        outs.writeObject(clePublic);
        outs.flush();

        // il récupère la clé DES chifrée
        byte[] DESencode = ins.readNBytes(128);

        // il déchiffre la clé DES
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, clePrivate);
        byte[] keyDESDecode = cipher.doFinal(DESencode);
        cleDES = new SecretKeySpec(keyDESDecode,0,keyDESDecode.length,"DES");

    }
}


