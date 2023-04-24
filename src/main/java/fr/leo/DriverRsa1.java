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
		 * On g�n�re une paire de cl�s math�matiquement li�es : une priv�e, une publique
		 */
		KeyPairGenerator keyPairGenerator =  KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(1024); // Longueur de la cl� ( 512 ou 1024 ! )
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		PrivateKey privateKey = keyPair.getPrivate();
		PublicKey publicKey = keyPair.getPublic();
		
		System.out.println(Arrays.toString(privateKey.getEncoded())); // La cl� priv�e est beaucoup plus grande que la cl� publique !
		System.out.println(Arrays.toString(publicKey.getEncoded()));	
		System.out.println();
		
		// On encode les cl�s au format Base64. C'est de cette mani�re que on les stocke habituellement. 
		String encodePrivateToString = Base64.getEncoder().encodeToString(privateKey.getEncoded()); 
		System.out.println(encodePrivateToString);
		
		
			
		String encodePublicToString = Base64.getEncoder().encodeToString(publicKey.getEncoded());
		System.out.println(encodePublicToString);
		
		/*
		 * Maintenant on va crypter avec la cl� publique,
		 *  et ensuite je suis le seul � pouvoir d�crypter avec la cl� priv�e !
		 */
	}
}
