package ma.enset;

import ma.enset.encryption.CryptoUtilImpl;

public class TestSignature {

	public static void main(String[] args) throws Exception {
		CryptoUtilImpl cryptoUtil=new CryptoUtilImpl();
		String secret="qwerty";
		String message="this is my message";
		String signature=cryptoUtil.hmacSign(message.getBytes(), secret);
		String signedDoc=message+"_.._"+signature;
		System.out.println(signedDoc);
		System.out.println("Signature verification");
		boolean signatureVerify=cryptoUtil.hmacVerify("this is my message_.._HF+BKGd1l4fcW6uIy8gaZbRvGkIAp1qPH0QmbSLWDAo=","qwerty");
		System.out.println(signatureVerify==true?"Signature ok":"Signature not ok");
	}

}
