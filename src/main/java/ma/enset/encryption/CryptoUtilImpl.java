package ma.enset.encryption;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.security.cert.*;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Formatter;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

import org.apache.commons.codec.binary.Hex;

public class CryptoUtilImpl {
	
	public String toBase64(byte[] data) {
		return Base64.getEncoder().encodeToString(data);
		}
	public byte[] fromBase64(String dataBase64) {
		return Base64.getDecoder().decode(dataBase64.getBytes());
	}
	public String toBase64Url(byte[] data) {
		return Base64.getUrlEncoder().encodeToString(data);
		}
	public byte[] fromBase64Url(String dataBase64) {
		return Base64.getUrlDecoder().decode(dataBase64.getBytes());
	}
	public String encodeToHex(byte[] data) {
		return DatatypeConverter.printHexBinary(data);
	}
	public String encodePatch(byte[] data) {
		return Hex.encodeHexString(data);
	}
	
	public String encodeToHexNative(byte[] data) {
		Formatter formatter=new Formatter();
		for (byte b : data) {
			formatter.format("%02x",b);
		}
		return formatter.toString();
		
	}
	public SecretKey generateSecretKey() throws Exception {
		KeyGenerator keyGenerator=KeyGenerator.getInstance("AES");
		keyGenerator.init(256);
		return keyGenerator.generateKey();
	}
	
	public SecretKey generateSecretKey(String secret) throws Exception {
		SecretKey secretKey=new SecretKeySpec(secret.getBytes(),0,secret.length(),"AES");
		
		return secretKey;
	}
	
	public String encrypteAES(byte[] data, SecretKey secretKey) throws Exception  {
		 Cipher cipher=Cipher.getInstance("AES");
		 cipher.init(Cipher.ENCRYPT_MODE,secretKey);
		 byte[] encrypData=cipher.doFinal(data);
		 String encodedEncrypData=Base64.getEncoder().encodeToString(encrypData);
		 return encodedEncrypData;
	}
	
	public byte[] dencrypteAES(String encodedEncryptedData, SecretKey secretKey) throws Exception  {
		 byte[] decode=Base64.getDecoder().decode(encodedEncryptedData);
		 Cipher cipher=Cipher.getInstance("AES");
		 cipher.init(Cipher.DECRYPT_MODE,secretKey);
		 
		 byte[] decryptedBytes=cipher.doFinal(decode);
		 return decryptedBytes;
	}
	public KeyPair generateKeyPair() throws  Exception {
		KeyPairGenerator keyPairGenerator=KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(512);
		return keyPairGenerator.generateKeyPair();
	}
	
	public PublicKey publicKeyFormBase64(String pkBase64) throws Exception {
		KeyFactory keyFactory=KeyFactory.getInstance("RSA");
		byte[] decodePK=Base64.getDecoder().decode(pkBase64);
		PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(decodePK));
		return publicKey;
	}
	
	public PrivateKey privateKeyFormBase64(String pkBase64) throws Exception {
		KeyFactory keyFactory=KeyFactory.getInstance("RSA");
		byte[] decodePK=Base64.getDecoder().decode(pkBase64);
		PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(decodePK));
		return privateKey;
	}
	
	public String encryptRSA(byte[] data,PublicKey pbKey) throws Exception {
		Cipher cipher=Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE,pbKey );
		byte[] bytes=cipher.doFinal(data);
		return toBase64(bytes);
	}
	
	public byte[] decryptRSA(String dataBase64, PrivateKey prKey) throws Exception {
		Cipher cipher=Cipher.getInstance("RSA");
		cipher.init(Cipher.DECRYPT_MODE,prKey );
		byte[] decodedEncryptrdData=Base64.getDecoder().decode(dataBase64);
		byte[] decryptedData=cipher.doFinal(decodedEncryptrdData);
		return decryptedData;
	}
	
	public PublicKey publicKeyFromCertificate(String fileName) throws Exception {
		FileInputStream fileInputStream=new FileInputStream(fileName);
		CertificateFactory certifFactory=CertificateFactory.getInstance("X.509");
		Certificate certificate=certifFactory.generateCertificate(fileInputStream);
		System.out.println(certificate.toString());
		return certificate.getPublicKey();
	}
	
	public PrivateKey privateKeyFromJKS(String jksFileName, String keyStorePassword,String alias) throws Exception {
		FileInputStream fileInputStream=new FileInputStream(jksFileName);
		KeyStore keyStore=KeyStore.getInstance(KeyStore.getDefaultType());
		keyStore.load(fileInputStream,keyStorePassword.toCharArray());
		Key key=keyStore.getKey(alias,keyStorePassword.toCharArray());
		PrivateKey privateKey= (PrivateKey) key;
		
		return privateKey;
	}
	public String hmacSign(byte[] data,String privateSecret) throws Exception {
		SecretKeySpec secretKeySpec=new SecretKeySpec(privateSecret.getBytes(),"HmacSHA256");
		Mac mac=Mac.getInstance("HmacSHA256");
		mac.init(secretKeySpec);
		byte[] signature=mac.doFinal(data);
		return Base64.getEncoder().encodeToString(signature);
	}
	
	public boolean hmacVerify(String signedDocument, String secret) throws Exception {
		SecretKeySpec secretKeySpec=new SecretKeySpec(secret.getBytes(),"HmacSHA256");
		Mac mac=Mac.getInstance("HmacSHA256");
		String[] splitedDocument=signedDocument.split("_.._");
		String document=splitedDocument[0];
		String signature=splitedDocument[1];
		mac.init(secretKeySpec);
		byte[] sign=mac.doFinal(document.getBytes());
		String base64Sign=Base64.getEncoder().encodeToString(sign);
		return (base64Sign.equals(signature));
	}
	
	public String rsaSign(byte[] data,PrivateKey prkey) throws Exception {
		Signature signature=Signature.getInstance("SHA256withRSA");
		signature.initSign(prkey,new SecureRandom());
		signature.update(data);
		byte[] sign=signature.sign();
		
		return Base64.getEncoder().encodeToString(sign);
	}
	
	public boolean rsaVerify(String signedDocument,PublicKey pubkey) throws Exception {
		Signature signature=Signature.getInstance("SHA256withRSA");
		signature.initVerify(pubkey);
		String[] data=signedDocument.split("_.._");
		String document=data[0];
		String sign=data[1];
		byte[] decodedSign=Base64.getDecoder().decode(sign);
		signature.update(document.getBytes());
		boolean verify=signature.verify(decodedSign);
		
		return verify;
	}
}
