package fr.leo;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

public class DriverRsaTestFinal7 {

	public static void main(String[] args) throws Exception {
		
		System.out.println("GENERATION DES CLES :");
		CryptoUtilImpl cryptoUtilImpl = new CryptoUtilImpl();
		KeyPair keyPair = cryptoUtilImpl.generateKeyPair(); // C'est aléatoire !
		PublicKey publicKey = keyPair.getPublic();
		
		String pkBase64 = cryptoUtilImpl.encodeToBase64(publicKey.getEncoded());
		System.out.println(pkBase64);
		
		PrivateKey privateKey = keyPair.getPrivate();
		
		String privateKeyBase64 = cryptoUtilImpl.encodeToBase64(privateKey.getEncoded());
		System.out.println(privateKeyBase64);
		
		System.out.println("\n CRYPTAGE :");
		PublicKey publicKey2 = cryptoUtilImpl.publicKeyFromBase64(pkBase64);		
		
		String data = "Voici Mon Message";
		System.out.println("Message : " + data  );
		
		String encrypted = cryptoUtilImpl.encryptRSA(data.getBytes(), publicKey2);
		System.out.println("Message encrypté : " + encrypted);
		
		System.out.println("\n DECRYPTAGE :");
		PrivateKey privateKey2 = cryptoUtilImpl.privateKeyFromBase64(privateKeyBase64);
		byte[] decrypted = cryptoUtilImpl.deryptRSA(encrypted, privateKey2);
		System.out.println("Message décrypté : " + new String(decrypted));
		
		// Les parties "génération des clée, cryptage, décryptage,
		//  normalement ce sont 3 applications séparées !
	}

}
