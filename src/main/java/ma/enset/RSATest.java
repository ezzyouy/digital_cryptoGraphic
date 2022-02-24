package ma.enset;

import java.security.*;

import ma.enset.encryption.CryptoUtilImpl;

public class RSATest {

	public static void main(String[] args) throws Exception {
		CryptoUtilImpl cryptoUtil=new CryptoUtilImpl();
		KeyPair keyPair=cryptoUtil.generateKeyPair();
		PublicKey pubKey=keyPair.getPublic();
		String pkBase64=cryptoUtil.toBase64(pubKey.getEncoded());
		System.out.println(pkBase64);
		PrivateKey prKey=keyPair.getPrivate();
		String prKBase64=cryptoUtil.toBase64(prKey.getEncoded());
		System.out.println(prKBase64);
		System.out.println("====================================");
		PublicKey publicKey1=cryptoUtil.publicKeyFormBase64(pkBase64);
		String data="Hello world...";
		String encrypted=cryptoUtil.encryptRSA(data.getBytes(),publicKey1);
		System.out.println("Encrypted: ");
		System.out.println(encrypted);
		
		PrivateKey prkey1=cryptoUtil.privateKeyFormBase64(prKBase64);
		System.out.println("Decrypted: ");
		byte[] bytes=cryptoUtil.decryptRSA(encrypted,prkey1);
		System.out.println(new String(bytes));
	}
}
