package fr.leo;

import java.security.PrivateKey;
import java.security.PublicKey;

public class DriverTestRsaSignature10 {

	public static void main(String[] args) throws Exception {
		
		CryptoUtilImpl cryptoUtilImpl = new CryptoUtilImpl();
		
		/* ON GENERE LA SIGNATURE
		 * 				APPLICATION A :
		 */
		
//		KeyPair keyPair = cryptoUtilImpl.generateKeyPair();// genere une paire de clés aléatoires
//		PublicKey publicKey = keyPair.getPublic();
//		PrivateKey privateKey = keyPair.getPrivate();
		
		/*
		 * On génere les clés à partir du store
		 */
		PrivateKey privateKey = cryptoUtilImpl.publicKeyFromJKS("rere.jks", "rerere", "rere");
		String data = "This is my message";
		String signature = cryptoUtilImpl.rsaSign(data.getBytes(), privateKey);
		String signedDoc =  data + "_.._" + signature;
		System.out.println(signedDoc);
		
		
		
		/* ON GENERE LA SIGNATURE
		 * 					APPLICATION B :
		 */
		System.out.println("");
		System.out.println("Signature verification ");
		
		String signedDocReceived ="This is my message_.._ZLqWlU8eu5pykQ8kuqhPEpF/4ULNKEHop/id5x69yDFCyzbZO9/Cvvnzjo+uYWJvFyVmBTW2R2+vvbPba0dsQ7ji+k06YQGBrqRfzz2fc03tP8EyH/QRNG+5u+ANYWPp22Loy+G/mjzbh5rsuSLadV8c4d62L8DjlFbvqw4YEi1DJmjA8JXvZZsD1AHkgXZBAWI1R5URaeJjc4dkNBiF9rGKQs13HbyuB+SadZc5oBJrnojPX1AOL+9XZIpS2ScNLJMpif7TO8+GileAAmz2EA+a+uk0bfs0yNtH2vNGi1ty/SVaAsVSIdpZQ8ffI4wp4CNSOASZ4hF/8fGbSlKd6Q==";
		PublicKey publicKey = cryptoUtilImpl.publicKeyFromCertificate("myCertificate.cert");
		boolean b =   cryptoUtilImpl.rsaSignVerify(signedDocReceived, publicKey);// je verifie est ce que ce document la est bien signé, est ce que je peux lui faire confiance
		System.out.println(b == true ? "Signature OK " : "Signature not OK" );
	}

}
