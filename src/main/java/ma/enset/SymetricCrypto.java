package ma.enset;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

import ma.enset.encryption.CryptoUtilImpl;

public class SymetricCrypto {

	public static void main(String[] args) throws Exception{
		
		
		 CryptoUtilImpl cryptoUtil=new CryptoUtilImpl();
		 SecretKey secretKey=cryptoUtil.generateSecretKey();
		 SecretKey secretKey2=cryptoUtil.generateSecretKey("azerty_qwerty_az");
		 byte[] encodedSecretKeyBytes=secretKey2.getEncoded();
		 System.out.println(Arrays.toString(encodedSecretKeyBytes));
		
		 String encodedSecretkey=Base64.getEncoder().encodeToString(encodedSecretKeyBytes);
		 System.out.println(new String(encodedSecretkey));
		 String data="hallo hest...";
		 String encryptedData =cryptoUtil.encrypteAES(data.getBytes(),secretKey2);
		
		 System.out.println(encryptedData);
		 
		 byte[] decrededData=cryptoUtil.dencrypteAES(encryptedData,secretKey2);
		 System.out.println(new String(decrededData));
	}
}
