package fr.leo;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;

public class DriverRsaTestFinal6 {

	public static void main(String[] args) throws Exception {
		
		CryptoUtilImpl cryptoUtilImpl = new CryptoUtilImpl();
		KeyPair keyPair = cryptoUtilImpl.generateKeyPair(); // C'est al�atoire !
		PublicKey publicKey = keyPair.getPublic();
		PrivateKey privateKey = keyPair.getPrivate();
		
		String data = "Voici Mon Message";
		System.out.println("Message : " + data  );
		
		String encrypted = cryptoUtilImpl.encryptRSA(data.getBytes(), publicKey);
		System.out.println("Message encrypt� : " + encrypted);
		
		byte[] decrypted = cryptoUtilImpl.deryptRSA(encrypted, privateKey);
		System.out.println("Message d�crypt� : " + new String(decrypted));
	}

}
