package fr.leo;

import java.security.PrivateKey;
import java.security.PublicKey;

public class DriverTestKeystoreRsaJks8 {

	public static void main(String[] args) throws Exception {
		
		CryptoUtilImpl cryptoUtilImpl = new CryptoUtilImpl();
		PublicKey publicKey = cryptoUtilImpl.publicKeyFromCertificate("myCertificate.cert");
		PrivateKey privateKey = cryptoUtilImpl.publicKeyFromJKS("rere.jks", "rerere", "rere");

		System.out.println( cryptoUtilImpl.encodeToBase64(publicKey.getEncoded()));
		System.out.println(cryptoUtilImpl.encodeToBase64(privateKey.getEncoded()));
		
		String data = "My secret message";
		String encrypted = cryptoUtilImpl.encryptRSA(data.getBytes(), publicKey);
		System.out.println("Encrypted :");
		System.out.println(encrypted);
		
		byte[] decrypted =  cryptoUtilImpl.deryptRSA(encrypted, privateKey);
		System.out.println("Decrypted :");
		System.out.println(new String(decrypted));
		
		
		
		
	}

}
