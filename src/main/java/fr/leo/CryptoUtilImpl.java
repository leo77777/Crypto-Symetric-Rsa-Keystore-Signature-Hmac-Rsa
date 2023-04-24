package fr.leo;

import java.io.FileInputStream;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Formatter;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

import org.apache.commons.codec.binary.Hex;

public class CryptoUtilImpl {
	
	/*
	 * ENCODAGE BASE64 :	 *   
	 *  // "aaa" correspond à la suite binaire : 01100001 01100001 01100001
	 *	// Cette suite binaire codée en 6 bits : 011000 010110 000101 100001
	 *	// Cette suite binaire codée en 6 bits :   24      22  	 5		33
	 *	// Cette suite vaut en base64          :    Y      W     F       h
	 *	// Cette suite de lettres codée  Ascci :    89     87    70     104 
 	 *
	 *  Au final avec Base64, on peut transmettre un document binaire ( comme une photo,
	 *  ou un fichier pdf), on peut le transmettre au format caracteres ( par exemple
	 *  le protocol http qui nécessite une transmission de caractères )
	 */	
		
	
	/*
	 * VOUS AVEZ DES DONNEES BINAIRES, 
	 *     VOUS VOULEZ LEZ ECRIRE, LES ENCODER AU FORMAT TEXTE.
	 *     ET BIEN ON PEUT ENCODER :   EN BASE64
	 *        						   EN BASE64URL
	 *         						   EN HEXADECIMAL
	 */
	


	 /*	********************************************************************************************
	  *  	***** ENCODAGE D'UN TABLEAU DE BYTES SOUS FORME DE CHAINE DE CARACTERES BASE64 ******  *
	  * 	    ***** DECODAGE D'UNE CHAINE DE CARACTERES BASE64 EN TABLEAU DE BYTES *****         *
	  *  *******************************************************************************************

	  * METHODES POUR ENCODER UN TABLEAU DE BYTES ( tableau de bytes, obtenu par exemple
	  * 	suite à lecture d'un fichier binaire ( série de bits ) )
	  *  SOUS LA FORME UNE STRING EN BASE64 OU BASE64URL
	  *  
	  * METHODES POUR DECODER UNE STRING EN BASE64 OU BASE64URL
	  *  LE RESULTAT EST DONNE SOUS LA FORME D'UN TABLEAU DE BYTES 
	  *  ( Ensuite la lecture de tous les bytes du tableau,
	  *    permettent de reconstituer la suite de bits du document original)
	  *  
	  * On encode sous format texte, un document au format binaire
	  * On decode le format texte, et on reconstitue le document binaire
      *
	  * 
	  * encodeToString() :
	  * 	  	representation sous forme de caracteres Ascii
	  *    		du résultat du codage en base64 ("aaa" => YWFh )
	  * encode() : 
	  * 		representation sous forme de byte, du résultat du codage
	  *  		en base64 ("aaa" => 89 87 70 104 ) 
	  */	
	public String encodeToBase64(byte[] data) {
		return Base64.getEncoder().encodeToString(data);	
	}	
	public byte[] decodeFromBase64(String dataBase64) {
		return Base64.getDecoder().decode(dataBase64.getBytes());	
	}	
	public String encodeToBase64URL(byte[] data) {
		return Base64.getUrlEncoder().encodeToString(data);				
	}	
	public byte[] decodeFromBase64URL(String dataBase64URL) {
		return Base64.getUrlDecoder().decode(dataBase64URL.getBytes());	
	}	
	
	
	
        
	 /* 
	 * Solution avec jaxB présent dans le jdk jusqu'a java8 !
	 * Apres il faut inclure la dépendance dans le pom.xml !
	 */
	 /* *********************************************************************************
	  * 	       ***** ENCODAGE D'UN TABLEAU DE BYTES AU FORMAT HEXADECIMAL *****     * 
	  * 		   ***** LE RESULTAT EST UNE CHAINE DE CARACTERES             *****     *
	  * 	EN BYTE [84, 104, 105, 115, 32, 105, 115, 32, 109, 121,                     *
	  *               32, 109, 101, 115, 115, 97, 103, 101, 62, 62, 62]                 *
	  *     EN HEXA 54 68 69 73 20 69 73 20 6D 79 20 6D 65 73 73 61 67 65 3E 3E 3E      *                    *
	  * *********************************************************************************
	  */
	public String encodeToHex(byte[] data) {
		return DatatypeConverter.printHexBinary(data); // Avex Jaxb !
	}
	public byte[] decodeToHex(String dataHexa) {
		return DatatypeConverter.parseHexBinary(dataHexa);
	}
	
	
	
	
	
	 /* *********************************************************************************
	 * 	       ***** ENCODAGE D'UN TABLEAU DE BYTES AU FORMAT HEXADECIMAL *****         * 
	 * 		   ***** LE RESULTAT EST UNE CHAINE DE CARACTERES             *****         *
	 * 	EN BYTE [84, 104, 105, 115, 32, 105, 115, 32, 109, 121,                         *
	 *               32, 109, 101, 115, 115, 97, 103, 101, 62, 62, 62]                  *
	 *     EN HEXA 54 68 69 73 20 69 73 20 6D 79 20 6D 65 73 73 61 67 65 3E 3E 3E       *                    *
	 * **********************************************************************************
	 *
	 * Dans le cas ou on a pas JaxB, on peut utiliser la librairir "common-codec" !
	 * Librairie disponible depuis java4 et avant java8 !
	 * Solution avec la librairie Apache que on a mis dans le pom.xml :
	 *  "commons-codec" !
	 *  Cette librairie est trés utilisée dans les projets !
	 *  C'est une librairie Apache.
	 *  	<dependency>
	 *   		<groupId>commons-codec</groupId>
	 *  		<artifactId>commons-codec</artifactId>
	 *   		<version>1.15</version>
	 *      </dependency>
	 */
	public String encodeToHexApacheCodec(byte[] data) {
		return Hex.encodeHexString(data);
	}
	
	
	
	
	
	 /* *********************************************************************************
	 * 	       ***** ENCODAGE D'UN TABLEAU DE BYTES AU FORMAT HEXADECIMAL     *****     * 
	 * 		   ***** LE RESULTAT EST UNE CHAINE DE CARACTERES                 *****     *
	 * 	EN BYTE [84, 104, 105, 115, 32, 105, 115, 32, 109, 121,                         *
	 *               32, 109, 101, 115, 115, 97, 103, 101, 62, 62, 62]                  *
	 *     EN HEXA 54 68 69 73 20 69 73 20 6D 79 20 6D 65 73 73 61 67 65 3E 3E 3E       *  
	 * **********************************************************************************
	 * 
	 * Solution perso
	 */
	public String encodeToHexNative(byte[] data) {
		Formatter formatter = new Formatter();
		for (byte b : data) {
			formatter.format("%02x", b);
		}
		return formatter.toString();
	}
	
	//	GENERER UNE CLE SECRETE : pour le codage symetrique
	public SecretKey generateSecretKey() throws Exception {
		KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
		keyGenerator.init(128); // on l'initialise à 128 bits. Ici on peut augmenter => 192 ou 256 !
		return keyGenerator.generateKey();
	}
	public SecretKey generateSecretKey(String secret) throws Exception {
		SecretKey secretKey = new SecretKeySpec(secret.getBytes(), 0, secret.length(),"AES");
		return secretKey;
	}
	
	
	
	/*
	 * CRYPTAGE SYMETRIQUE AES
	 */
	public String encrypteAES(byte[] data, String secret) throws Exception  {
		Cipher cipher = Cipher.getInstance("AES");
		SecretKey secretKey = new SecretKeySpec(secret.getBytes(), 0, secret.length(), "AES"); // 0 : position du 1er caractere de la clé
		cipher.init(Cipher.ENCRYPT_MODE, secretKey); // ici on précise que on veut encrypter ( pas décrypter !)
		byte[] encrytedData = cipher.doFinal(data); // ici, on crypte !  => i7lCh£Nrt”Vd†OzJ±¸]ö?6šjÖð«×‡×
		String encodedEncryptedData = Base64.getEncoder().encodeToString(encrytedData); // Maintenant, on l'encode au format texte
		return encodedEncryptedData;
	}
	// Version avec le tpye "SecretKey" en parametre 
	public String encrypteAES(byte[] data, SecretKey secretKey) throws Exception  {
		Cipher cipher = Cipher.getInstance("AES");
		// SecretKey secretKey = new SecretKeySpec(secret.getBytes(), 0, secret.length(), "AES"); // 0 : position du 1er caractere de la clé
		cipher.init(Cipher.ENCRYPT_MODE, secretKey); // ici on précise que on veut encrypter ( pas décrypter !)
		byte[] encrytedData = cipher.doFinal(data); // ici, on crypte !  => i7lCh£Nrt”Vd†OzJ±¸]ö?6šjÖð«×‡×
		String encodedEncryptedData = Base64.getEncoder().encodeToString(encrytedData); // Maintenant, on l'encode au format texte
		return encodedEncryptedData;
	}
	
	public byte[] decrypteAES(String encodedEncryptedData, String secret) throws Exception  {		
		byte[] decodeEncryptedData = Base64.getDecoder().decode(encodedEncryptedData);			
		SecretKey secretKey = new SecretKeySpec(secret.getBytes(), 0 , secret.length(), "AES");
		Cipher cipher = Cipher.getInstance("AES");
		cipher.init(Cipher.DECRYPT_MODE, secretKey); 	// on précise que on veut decrypter !		
		byte[] decryptedBytes = cipher.doFinal(decodeEncryptedData); // on décrypte !
		return decryptedBytes;
	}	
	// Version avec le tpye "SecretKey" en parametre 
	public byte[] decrypteAES(String encodedEncryptedData, SecretKey secretKey) throws Exception  {		
		byte[] decodeEncryptedData = Base64.getDecoder().decode(encodedEncryptedData);			
		// SecretKey secretKey = new SecretKeySpec(secret.getBytes(), 0 , secret.length(), "AES");
		Cipher cipher = Cipher.getInstance("AES");
		cipher.init(Cipher.DECRYPT_MODE, secretKey); 	// on précise que on veut decrypter !		
		byte[] decryptedBytes = cipher.doFinal(decodeEncryptedData); // on décrypte !
		return decryptedBytes;
	}
	

	
					// CRYPTAGE ASYMETRIQUE 
	
	// CRYPTAGE ASYMETRIQUE : obtenir un générateur de paire de clés RSA
	public KeyPair generateKeyPair() throws Exception {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(512); // 512, 1024, ...
		return keyPairGenerator.generateKeyPair();		
	}	
	
	// GENERER UNE CLE PUBLIQUE RSA : on donne une clé encodée en Base64 et on la décode
	public PublicKey publicKeyFromBase64(String pkBase64) throws Exception {
		byte[] decodedPK = Base64.getDecoder().decode(pkBase64);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");		
		PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(decodedPK));
		return publicKey;
	}
	// GENERER UNE CLE PRIVEE RSA : on donne une clé encodée en Base64 et on la décode
	public PrivateKey privateKeyFromBase64(String pkBase64) throws Exception {
		byte[] decodedPK = Base64.getDecoder().decode(pkBase64);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");		
		PrivateKey privateKey  = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(decodedPK) );
		return privateKey;
	}
	// CRYTAGE RSA AVEC CLE PUBLIQUE
	public String encryptRSA(byte[] data , PublicKey publicKey) throws Exception {
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);
		byte[] bytes = cipher.doFinal(data);
		return encodeToBase64(bytes); // notre propre methode !
		//return Base64.getEncoder().encodeToString(bytes);
	}
	// DECRYPTAGE RSA AVEC CLE PRIVEE
	public byte[] deryptRSA(String dataBase64 , PrivateKey privateKey ) throws Exception {
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.DECRYPT_MODE, privateKey);
		byte[] decodedEncryptedData = decodeFromBase64(dataBase64);		
		byte[] decryptedData = cipher.doFinal(decodedEncryptedData);		
		return decryptedData;
	}
	
	// Methode permettant de retourner la clé publique du keyStore 
	// La clé public on la genere à partir du fichier
	public PublicKey publicKeyFromCertificate(String filename) throws Exception {
		FileInputStream fileInputStream = new FileInputStream(filename);
		CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509"); // format du certificat
		Certificate certificate = certificateFactory.generateCertificate(fileInputStream);
		System.out.println("********************************************");
		System.out.println(certificate.toString());
		System.out.println("********************************************");
		return certificate.getPublicKey();
	}
	
	// Pour lire la clé privée à partir du fichier .jks
	// La clé privée on la genere à partir du fichier .jks
	public PrivateKey publicKeyFromJKS(String filename , String jksPassword, String alias ) throws Exception {
		FileInputStream fileInputStream = new FileInputStream(filename);
		KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType()); // c'est le type de keystore, c'est celui utilisé avec l'outil "keytol" 
		keyStore.load(fileInputStream, jksPassword.toCharArray()); // on donne le mot de passe
		Key key = keyStore.getKey(alias, jksPassword.toCharArray());
		PrivateKey privateKey = (PrivateKey) key;
		return privateKey;		
	}
	
	
	/*
	 * 					GENERER UNE SIGNATURE POUR UN DOCUMENT
	 * 
	 * Deux méthodes possibles : Hmac et rsa
	 * Une signature, c'est un code, basé sur un Hash généré pour le document.
	 * Générer un hash ça veut dire que à partir d'un document,
	 *  on va utiliser un algorithme comme HmacSHA256
	 * 
	 * 
	 */

	/* 
	 * GENERER UNE SIGNATURE AVEC HMAC  ( Hash Message Authentification Code )
	 * Méthode qui permet de generer la signature d'un document.
	 * La signature est un String.
	 * 
	 * 	Avec Hmac, on utilise un secret pour genrerer la signature,
	 *    et le meme secret pour vérifier la signature. Pour crypter et decrypter.
	 * 
	 * 	En entrée :
	 *	 byte[]  dataToSign : c'est le document à signer, il est sous la forme d'un tableau de bytes.
	 *						  C'est un document au format binaire 
	 *	 String privateSecret : avec Hmac, on utilise un secret, un secret qui est symétrique, cad 
	 *				       que on va utiliser ce secret pour générer la signature, 
	 *				       et ensuite on utilise ce meme secret pour vérifier la signature.
	 *	En sortie : la signature sera un String !
	 */
	 public String hmacSign( byte[]  dataToSign,  String privateSecret) throws Exception {
		
		// On creer une cle secrete, un code qui permet d'authentifier le message
		// On genere un hash, en utilisant l'algo de hashage "SHA256"
		SecretKeySpec secretKeySpec = new SecretKeySpec(privateSecret.getBytes(), "HmacSHA256");
		
		// On fait appel à l'algorithme Mac
		Mac mac = Mac.getInstance("HmacSHA256");
		mac.init(secretKeySpec);
		byte[] signature = mac.doFinal(dataToSign);
		return Base64.getEncoder().encodeToString(signature);
	}
	
	// Methode qui va verifier si un document signé avec Hmac n'a pas été falsifié
	public boolean hmacVerify(String signedDocument, String secret) throws Exception {
		SecretKeySpec secretKeySpec = new SecretKeySpec(secret.getBytes(), "HmacSHA256");
		Mac mac = Mac.getInstance("HmacSHA256");
		
		String[] splitedDocument = signedDocument.split("_.._");
		String document = splitedDocument[0];
		String documentSignature = splitedDocument[1];
		mac.init(secretKeySpec);
		byte[] sign = mac.doFinal(document.getBytes());
		String base64Sign = Base64.getEncoder().encodeToString(sign);
		return base64Sign.equals(documentSignature);
	}
	
	
	// GENERER UNE SIGNATURE AVEC RSA
	// On signe avec la clé privée
	//  et on verifit avec la clé publique !
	// Moi lorsque je signe un document, je suis le seul à connaitre la clé privée,
	//  et ensuite toutes les applications qui vont recevoir ce document,
	//  elles peuvent vérifier la signature avec la clé public, et donc avoir confiance dans le document !
	public String rsaSign( byte[]  dataToSign,  PrivateKey privateKey) throws Exception {
		Signature signature = Signature.getInstance("SHA256withRSA");
		signature.initSign(privateKey, new SecureRandom());
		signature.update(dataToSign);
		byte[] sign = signature.sign();
		return Base64.getEncoder().encodeToString(sign);
	}
	// VERIFIER LA SIGNATURE D'UN DOCUMENT AVEC RSA
	public boolean rsaSignVerify( String  signedDoc,  PublicKey publicKey) throws Exception {
		Signature signature = Signature.getInstance("SHA256withRSA");
		signature.initVerify(publicKey); // On peut aussi utiliser le certificat pour vérifier
		String[] data = signedDoc.split("_.._");
		String document = data[0];
		String sign = data[1];
		byte[] decodeSignature = Base64.getDecoder().decode(sign);
		signature.update(document.getBytes());
		boolean verify = signature.verify(decodeSignature);		
		return verify;
	}
}
