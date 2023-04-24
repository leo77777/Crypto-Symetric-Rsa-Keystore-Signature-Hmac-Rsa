package fr.leo;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

import javax.crypto.Cipher;

public class DriverRsaPlus2 {

	public static void main(String[] args) throws Exception {			
		
		CryptoUtilImpl cryptoUtilImpl = new CryptoUtilImpl();		
		KeyPair keyPair =  cryptoUtilImpl.generateKeyPair();
		PrivateKey privateKey = keyPair.getPrivate();
		PublicKey publicKey = keyPair.getPublic();	
		
		// System.out.println("Longueur : " + privateKey.getEncoded().length); // 344  La clé privée est beaucoup plus grande que la clé publique !
		// System.out.println(Arrays.toString(privateKey.getEncoded())); // [48, -126, 1, 84, 2, 1, 0, 48, 13, 6, 9, 42, -122, 72, -122, -9, 13, 1, 1, 1, 5, 0, 4, -126, 1, 62, 48, -126, 1, 58, 2, 1, 0, 2, 65, 0, -122, 75, 74, 77, 123, -1, -5, 114, -62, 96, 17, 113, 39, 55, 15, -35, 71, 15, -114, 101, 63, -96, 79, -119, -10, 64, 101, 103, -116, -6, -102, -17, -58, 59, 125, 58, 60, -90, 23, 93, 51, 8, -121, -22, 14, 4
																	  // -14, ...  17, -27, -70, -29, -57, ]																	
		String encodePrivateToString = Base64.getEncoder().encodeToString(privateKey.getEncoded()); // C'est comme cela que on les stocke généralement au format chaine de caractères 
		System.out.println("Private key : " + encodePrivateToString); // MIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT4wggE6AgEAAkEAhk
												   //  tKTXv/+ ...  3LCYBFxJzcP3UcPjmU/oE+J9kBlZ4z6mu
		
		System.out.println();
		
		// System.out.println("Longueur : " + publicKey.getEncoded().length); // 94
		// System.out.println(Arrays.toString(publicKey.getEncoded())); // [48, 92, 48, 13, 6, 9, 42, -122, 72, -122, -9, 13, 1, 1
																	 //  0, 3, 75, 0, 48, ... 0, -122, 75, 74, 77]
		String encodePublicToString = Base64.getEncoder().encodeToString(publicKey.getEncoded());
		System.out.println("Public key : " + encodePublicToString); // MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAIZLSk ... cSc3D91HD

		
		
		
		
		/*
		 * Maintenant on va crypter un message avec la clé publique,
		 *  et ensuite je suis le seul à pouvoir décrypter avec la clé privée !
		 */
		String data = "Voici mon message clair à chiffrer";
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);
		byte[] encryptedBytes = cipher.doFinal(data.getBytes());
		System.out.println("Message : " + data);
		System.out.println("Message encrypté : " + new String(encryptedBytes)); // Message encrypté : q™T?x>Ý‰´9*h]CËïTXVÃ+ J;Ï|ÞWÑÀö6	
																				// oArjÐÎ¿2á*‚JwÓŠ
		System.out.println( "Message encrypté plus Base64: " + Base64.getEncoder()
				.encodeToString(encryptedBytes)); // Message encrypté plus Base64: cZlUkHg+3Ym0OSpoXUPL71RYVgL
												  //  DKyBKO8983lfRwPY2CW8LQXIEatDOvzLhKoIHSnfTigpnrfzH4eQIu1EQeQ==
		
	}
}
