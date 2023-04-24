package fr.leo;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;

public class DriverCryptUsingGenerateRsaKeys5 {

	public static void main(String[] args) throws Exception {
		/* 
		 * 2 clés générées dans la classe "GenerateRsaKeys" !
		 * Private key : MIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT4wggE6AgEAAkEAqGODKgTQZo7NlC+UxXlMBE5WQbYdM/lXs3Dbol788vyfTCqYkw+XTFepAP3BtTbIbN4OPsaVjzr3pSYDAI2iBwIDAQABAkAHWdjHA9DJOWC2IGGhQUtVQMo5MicSNsdiWQHtk7H9NYHp6T14xxiYNhfDTHALIwhqaoe8WnlAeVflfMDtARKZAiEA0UdzT3b9PPuZm+W4EI3cXONdhS14ZYa0QY+Lp0zEWF0CIQDN+yC/T2HG6mf5eb6MPKR1m6vUa2Rp7lhT8Nu7BPGtswIgTeJvcZVw7W8dXb2CYPbKme8r8NJZSj91eii36o1RTSkCIQCg/hInVQ0wItAnbl9fTpqgDY8s1M9D+HVzDkM/lmqq/wIgQhmegUWfeYvZTaaSpdq2iqpqkJwmXLZb4jc2iNY03cg=
		 * Public key : MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAKhjgyoE0GaOzZQvlMV5TAROVkG2HTP5V7Nw26Je/PL8n0wqmJMPl0xXqQD9wbU2yGzeDj7GlY8696UmAwCNogcCAwEAAQ==
		*/
		
		String publicKeyBase64 = "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAKhjgyoE0GaOzZQvlMV5TAROVkG2HTP5V7Nw26Je/PL8n0wqmJMPl0xXqQD9wbU2yGzeDj7GlY8696UmAwCNogcCAwEAAQ==" ;
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		byte[] decodeKey = Base64.getDecoder().decode(publicKeyBase64);
		PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(decodeKey));
		

		String data = "Voici mon message clair à chiffrer";
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);
		byte[] encryptedBytes = cipher.doFinal(data.getBytes());
		System.out.println( "Message encrypté plus Base64: " + Base64.getEncoder().encodeToString(encryptedBytes)); 
	}
}
