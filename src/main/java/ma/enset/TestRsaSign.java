package ma.enset;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import ma.enset.encryption.CryptoUtilImpl;

public class TestRsaSign {

	public static void main(String[] args) throws Exception {
		CryptoUtilImpl cryUtil=new CryptoUtilImpl();
		
		PrivateKey prK=cryUtil.privateKeyFromJKS("brahim.jks","badboy","brahim");
		String data="this is my message";
		String signature=cryUtil.rsaSign(data.getBytes(),prK);
		String signedDoc=data+"_.._"+signature;
		System.out.println(signedDoc);
		System.out.println("=================================");
		System.out.println("Signature verification :");
		String signedDocRecieved="this is my message_.._NV1hlEIGHho8uIxrxBUlmBxgDli4+0aKyugnVcXe6V7tntFFVIunatemQZ/dRspvxYwcTTav1EXf8KPFbcbZjPoWAlVSJXo5jDjWe5lKQWQlmkoslL4rnOqYpzCN4ky8fIB+IZhzVblnYJ7avcSBdkeaT215tksByN4DsYtQDb84qT34POM0MQj64ohy31krl0zNefUYi1RWX+8iLE59bxvZynFJq93JGnE4Jq3RTTRNIVdEzSmIVrKqsmlFxkpEBUPgigHerGtaGTlqta6c+l/06sdodsfD4qSpPJskbRGtKIclyra5kGJ5LMTCeBYRYNSfwxgLaWZE+BkuQEqsVA==";
		PublicKey pubK=cryUtil.publicKeyFromCertificate("myCertificate.cert");
		boolean b=cryUtil.rsaVerify(signedDocRecieved,pubK);
		System.out.println(b?"signature ok":"signature not ok");
	}

}
