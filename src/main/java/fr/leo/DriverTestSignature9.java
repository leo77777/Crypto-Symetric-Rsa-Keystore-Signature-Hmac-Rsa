package fr.leo;

public class DriverTestSignature9 {

	public static void main(String[] args) throws Exception {
		
		/*
		 * 					APPLICATION A : ELLE GENERE LA SIGNATURE
		 */
		String document = "This is my message"; // Ca peut etre un document xml, ...
		CryptoUtilImpl cryptoUtilImpl = new CryptoUtilImpl();
		String secret = "azerty"; // Avec ce mot de passe, je peux generer la signature
		String signature = cryptoUtilImpl.hmacSign(document.getBytes(), secret);
		
		String signedDocument = document + "_.._" + signature; // si on a un document pdf, la il y a une place speciale pour la signature
		
		System.out.println(signedDocument); // => This is my message_.._oWfD3YCesNpVWhygSPBzF+N9X8NJpa2wyxBe6MZB6V8=
											// On a toujours la meme valeur, meme si on relance l'appli plusieurs fois !
		
		/*
		 * 					APPLICATION B : ELLE VERIFIE LA SIGNATURE 
		 */		
		// Maintenant , si vous me transmettez ce docuement :
		//  This is my message_.._oWfD3YCesNpVWhygSPBzF+N9X8NJpa2wyxBe6MZB6V8=
		//    comment vais je m'assurer que il n'a pas été modifié !
		
		// Celui qui recoit le document, il doit vérifier la signature !
		// Et bien il va prendre le contenu du document,
		//   et si vous connaissez le secret , on va generer la signature,
		//     et ensuite on va la comparer avec la signature qui se trouve dans le document !
		
		String signedDoc = "This is my message_.._oWfD3YCesNpVWhygSPBzF+N9X8NJpa2wyxBe6MZB6V8="; 
		String sec = "azerty";
		System.out.println("Signature verification :");
		boolean signatureVerificationResult =  cryptoUtilImpl.hmacVerify(signedDoc, sec);
		System.out.println(signatureVerificationResult == true ? "Signature OK " : "Signature not OK" );
		
		
		/*
		 * L'inconvénient avec HMAC, c'est que on a une clé partagée !
		 * Et quand on a un secret partagé, ce n'est plus un secret !!!!
		 * Et donc on va utiliser rsa .
		 */
	}
}
