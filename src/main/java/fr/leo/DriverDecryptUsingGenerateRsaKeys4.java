package fr.leo;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;

public class DriverDecryptUsingGenerateRsaKeys4 {

	public static void main(String[] args) throws Exception {
		/* 
		 * 2 clés générées dans la classe "GenerateRsaKeys" !
		 * Private key : MIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT4wggE6AgEAAkEAqGODKgTQZo7NlC+UxXlMBE5WQbYdM/lXs3Dbol788vyfTCqYkw+XTFepAP3BtTbIbN4OPsaVjzr3pSYDAI2iBwIDAQABAkAHWdjHA9DJOWC2IGGhQUtVQMo5MicSNsdiWQHtk7H9NYHp6T14xxiYNhfDTHALIwhqaoe8WnlAeVflfMDtARKZAiEA0UdzT3b9PPuZm+W4EI3cXONdhS14ZYa0QY+Lp0zEWF0CIQDN+yC/T2HG6mf5eb6MPKR1m6vUa2Rp7lhT8Nu7BPGtswIgTeJvcZVw7W8dXb2CYPbKme8r8NJZSj91eii36o1RTSkCIQCg/hInVQ0wItAnbl9fTpqgDY8s1M9D+HVzDkM/lmqq/wIgQhmegUWfeYvZTaaSpdq2iqpqkJwmXLZb4jc2iNY03cg=
		 * Public key : MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAKhjgyoE0GaOzZQvlMV5TAROVkG2HTP5V7Nw26Je/PL8n0wqmJMPl0xXqQD9wbU2yGzeDj7GlY8696UmAwCNogcCAwEAAQ==
		*/
		
		String privateKeyBase64 = "MIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT4wggE6AgEAAkEAqGODKgTQZo7NlC+UxXlMBE5WQbYdM/lXs3Dbol788vyfTCqYkw+XTFepAP3BtTbIbN4OPsaVjzr3pSYDAI2iBwIDAQABAkAHWdjHA9DJOWC2IGGhQUtVQMo5MicSNsdiWQHtk7H9NYHp6T14xxiYNhfDTHALIwhqaoe8WnlAeVflfMDtARKZAiEA0UdzT3b9PPuZm+W4EI3cXONdhS14ZYa0QY+Lp0zEWF0CIQDN+yC/T2HG6mf5eb6MPKR1m6vUa2Rp7lhT8Nu7BPGtswIgTeJvcZVw7W8dXb2CYPbKme8r8NJZSj91eii36o1RTSkCIQCg/hInVQ0wItAnbl9fTpqgDY8s1M9D+HVzDkM/lmqq/wIgQhmegUWfeYvZTaaSpdq2iqpqkJwmXLZb4jc2iNY03cg=" ;
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		byte[] decodeKey = Base64.getDecoder().decode(privateKeyBase64);
		PrivateKey privateKey  = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(decodeKey) );
		
		String 	encryptedData ="U8gf4fnH3k6w3R+nag4/bDBWL3ymAM+Usr86Y7GztaWtn4CBh3WLNDBlLtA8IW6cusbHlwQUJfIkI78MNyho+A==";
		System.out.println("Encrypted data : " + encryptedData);
		
		byte[] decodeEncryptedData = Base64.getDecoder().decode(encryptedData);
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.DECRYPT_MODE, privateKey);
		byte[] decryptedBytes = cipher.doFinal(decodeEncryptedData);
		System.out.println( "Message decrypté : " + new String(decryptedBytes)); 
		
	
		// REMARQUE : on peut inverser : cad crypter avec la cle privée et décriptée avec la clé public !
		//  Mais généralement c'est l'inverse : je partage la clé publique,
		//   et quand ils vont m'envoyer des données secrètes, ils peuvent utiliser la clé publique
		//   pour crypter, et lorsque je le recois, je suis le seul à etre capable de le décrypter,
		//   car je suis le seul à avoir la clé privée !
	}

}
