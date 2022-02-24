package ma.enset;

import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class DecrypthAESTest {

	public static void main(String[] args) throws Exception{
		 String encrypData2="+dzi4HPdjpJy2lP0+/gVNlXb6R+E+59Hju2MumvuUo8=";
		 byte[] decode=Base64.getDecoder().decode(encrypData2);
		 String mySecret="azerty_qwerty_az";
		 SecretKey secretKey=new SecretKeySpec(mySecret.getBytes(),0,mySecret.length(),"AES");
		 Cipher cipher=Cipher.getInstance("AES");
		 cipher.init(Cipher.DECRYPT_MODE,secretKey);
		 
		 byte[] bytes=cipher.doFinal(decode);
		 System.out.println(new String(bytes));
	}

}
