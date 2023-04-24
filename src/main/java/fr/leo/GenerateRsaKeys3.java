package fr.leo;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

/*
 * Ici on génère 2 clés et on les encode au format Base64 !
 */
public class GenerateRsaKeys3 {

	public static void main(String[] args) throws Exception {
		
		CryptoUtilImpl cryptoUtilImpl = new CryptoUtilImpl();		
		KeyPair keyPair =  cryptoUtilImpl.generateKeyPair();
		PrivateKey privateKey = keyPair.getPrivate();
		PublicKey publicKey = keyPair.getPublic();	
																			
		String encodePrivateToString = Base64.getEncoder().encodeToString(privateKey.getEncoded()); 
		System.out.println("Private key : " + encodePrivateToString); 
																
		String encodePublicToString = Base64.getEncoder().encodeToString(publicKey.getEncoded());
		System.out.println("Public key : " + encodePublicToString); 
	}
}
