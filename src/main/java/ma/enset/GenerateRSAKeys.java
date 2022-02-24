package ma.enset;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

import javax.crypto.Cipher;

import ma.enset.encryption.CryptoUtilImpl;

public class GenerateRSAKeys {

	public static void main(String[] args) throws Exception {
		
		CryptoUtilImpl crypto=new CryptoUtilImpl();
		KeyPair keyPair=crypto.generateKeyPair();
		PrivateKey privateKey = keyPair.getPrivate();
		PublicKey publicKey = keyPair.getPublic();
		System.out.println("privateKey :");
		//System.out.println(privateKey.getEncoded().length);
		//System.out.println(Arrays.toString(privateKey.getEncoded()));
		System.out.println(Base64.getEncoder().encodeToString(privateKey.getEncoded()));
		System.out.println("publicKey :");
		//System.out.println(publicKey.getEncoded().length);
		//System.out.println(Arrays.toString(publicKey.getEncoded()));
		System.out.println(Base64.getEncoder().encodeToString(publicKey.getEncoded()));
		
		
	}
	
}
