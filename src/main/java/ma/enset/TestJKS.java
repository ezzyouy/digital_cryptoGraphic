package ma.enset;

import java.security.*;

import ma.enset.encryption.CryptoUtilImpl;

public class TestJKS {

	public static void main(String[] args) throws Exception{
		CryptoUtilImpl cryptoUtil= new CryptoUtilImpl();
		PublicKey pubKey=cryptoUtil.publicKeyFromCertificate("myCertificate.cert");
		System.out.println(cryptoUtil.toBase64(pubKey.getEncoded()));
		PrivateKey privateKey=cryptoUtil.privateKeyFromJKS("brahim.jks","badboy","brahim");
		System.out.println(cryptoUtil.toBase64(privateKey.getEncoded()));
		
		String data="My secret message";
		String encrypted=cryptoUtil.encryptRSA(data.getBytes(),pubKey);
		System.out.println("encrypted: ");
		System.out.println(encrypted);
		byte[] decryptedBytes=cryptoUtil.decryptRSA(encrypted, privateKey);
		System.out.println("decrypted: ");
		System.out.println(new String(decryptedBytes));
		
		//=>HMAC: 
		//=>  RSAWithSHA250
	}
}
