package ma.enset;

import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;

import ma.enset.encryption.CryptoUtilImpl;

public class TestRSA {

	public static void main(String[] args) throws Exception {
		
		/*
privateKey :
MIIBVgIBADANBgkqhkiG9w0BAQEFAASCAUAwggE8AgEAAkEAkAbD/3Yj6uu0QVDKl0lIAlYBM/zXUvSD4CE5NbtHWePtfo4bHvk9bd1ryuwPAcEUA85TwLb7S5Bha6lhTHi9bwIDAQABAkEAjm9ydHk0ykZyTMoGoRli8pR1uiFKHYsdxJF2z7G3vafRtnuv/E9x2MrjE8hALGjujMic3fXBreFc/3EzVmjbWQIhANxhHa1HpOBvzHKiAG3Fn5PCTtKayBmpnyKzxmEa1SItAiEAp05PDBhGWkQhHN8b13COdQMG6OlpVNGd2EzUc1IsS4sCIQCHMVyPTIAs3ujA+fjhXnbColTQhftzIsdo9nggYeGWEQIhAI09IKJXQ90kMsgK2ZgwnzLNEWJC2fcO1rApfBi2wEotAiBeW/RbipXDR/AQ+fCIgTmhZTMkWuXo/mv5VOyzjzM7+w==
publicKey :
MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAJAGw/92I+rrtEFQypdJSAJWATP811L0g+AhOTW7R1nj7X6OGx75PW3da8rsDwHBFAPOU8C2+0uQYWupYUx4vW8CAwEAAQ==
		 */
		
		String privateKeyBase64="MIIBVgIBADANBgkqhkiG9w0BAQEFAASCAUAwggE8AgEAAkEAkAbD/3Yj6uu0QVDKl0lIAlYBM/zXUvSD4CE5NbtHWePtfo4bHvk9bd1ryuwPAcEUA85TwLb7S5Bha6lhTHi9bwIDAQABAkEAjm9ydHk0ykZyTMoGoRli8pR1uiFKHYsdxJF2z7G3vafRtnuv/E9x2MrjE8hALGjujMic3fXBreFc/3EzVmjbWQIhANxhHa1HpOBvzHKiAG3Fn5PCTtKayBmpnyKzxmEa1SItAiEAp05PDBhGWkQhHN8b13COdQMG6OlpVNGd2EzUc1IsS4sCIQCHMVyPTIAs3ujA+fjhXnbColTQhftzIsdo9nggYeGWEQIhAI09IKJXQ90kMsgK2ZgwnzLNEWJC2fcO1rApfBi2wEotAiBeW/RbipXDR/AQ+fCIgTmhZTMkWuXo/mv5VOyzjzM7+w==";
		KeyFactory keyFactory=KeyFactory.getInstance("RSA");
		byte[] decodedKey=Base64.getDecoder().decode(privateKeyBase64);
		PrivateKey privateKey=keyFactory.generatePrivate(new PKCS8EncodedKeySpec(decodedKey));
		
		
		String encryptedData="MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAJAGw/92I+rrtEFQypdJSAJWATP811L0g+AhOTW7R1nj7X6OGx75PW3da8rsDwHBFAPOU8C2+0uQYWupYUx4vW8CAwEAAQ==";
		System.out.println(encryptedData);
		System.out.println("Decrypted message : ");
		byte[] decodeEncryptedData=Base64.getDecoder().decode(encryptedData);
		Cipher cipher=Cipher.getInstance("RSA");
		cipher.init(Cipher.DECRYPT_MODE,privateKey);
		System.out.println(decodeEncryptedData);
		byte[] decryptedBytes=cipher.doFinal(Base64.getDecoder().decode(encryptedData));
		
		System.out.println(new String(decryptedBytes));
		
		
	}
}
