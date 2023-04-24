package fr.leo;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.net.URL;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Base64;

public class DriverRsa1 {

	public static void main(String[] args) throws Exception {

//		FileInputStream calc = new FileInputStream("cmd.txt");
//		FileOutputStream calcRes = new FileOutputStream("calc2.txt");
//		byte[] tab = new byte[1000];
//		byte[] res = null;
//		int a;
//		while( (a = calc.read(tab)) != -1 ) {
//			res = Base64.getEncoder().encode(tab);
//			calcRes.write(res);
//		}
//		calc.close();
//		calcRes.close();
//		
//		
//		byte[] tab2 = new byte[8];
//		byte[] res2 = null;
//		int a2;
//		FileInputStream calc2 = new FileInputStream("calc2.txt");
//		FileOutputStream calcRes2 = new FileOutputStream("calc3.txt");
//		while( (a2 = calc2.read(tab2)) != -1 ) {
//			res2 = Base64.getDecoder().decode(tab2);
//			calcRes2.write(res2);
//			tab2 = new byte[8];
//		}
//		calc2.close();
//		calcRes2.close();
		
		
		
		/*
		 * On génère une paire de clés mathématiquement liées : une privée, une publique
		 */
		KeyPairGenerator keyPairGenerator =  KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(1024); // Longueur de la clé ( 512 ou 1024 ! )
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		PrivateKey privateKey = keyPair.getPrivate();
		PublicKey publicKey = keyPair.getPublic();
		
		System.out.println(Arrays.toString(privateKey.getEncoded())); // La clé privée est beaucoup plus grande que la clé publique !
		System.out.println(Arrays.toString(publicKey.getEncoded()));	
		System.out.println();
		
		// On encode les clés au format Base64. C'est de cette manière que on les stocke habituellement. 
		String encodePrivateToString = Base64.getEncoder().encodeToString(privateKey.getEncoded()); 
		System.out.println(encodePrivateToString);
		
		
			
		String encodePublicToString = Base64.getEncoder().encodeToString(publicKey.getEncoded());
		System.out.println(encodePublicToString);
		
		/*
		 * Maintenant on va crypter avec la clé publique,
		 *  et ensuite je suis le seul à pouvoir décrypter avec la clé privée !
		 */
	}
}
