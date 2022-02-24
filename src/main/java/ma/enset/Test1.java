package ma.enset;

import java.util.Arrays;
import java.util.Base64;
import javax.xml.bind.DatatypeConverter;

import ma.enset.encryption.CryptoUtilImpl;

public class Test1 {

	public static void main(String[] args) {
		CryptoUtilImpl cry=new CryptoUtilImpl();
		String data="hello from there>>>";
		String base64=cry.toBase64(data.getBytes());
		String base64Url=cry.toBase64Url(data.getBytes());
		System.out.println(base64);
		System.out.println(base64Url);
		
		byte[] decodeBase64=cry.fromBase64(base64);
		byte[] decodeBase64Url=cry.fromBase64Url(base64Url);
		System.out.println(new String(decodeBase64));
		System.out.println(new String(decodeBase64Url));
		
		byte[] bytes=data.getBytes();
		System.out.println(Arrays.toString(bytes));
		String dataHex=DatatypeConverter.printHexBinary(bytes);
		System.out.println(dataHex);
		byte[] bytes1=DatatypeConverter.parseHexBinary(dataHex);
		System.out.println(new String(bytes1));
		
		String ss=cry.encodeToHex(data.getBytes());
		
		String sss=cry.encodePatch(data.getBytes());
	String s2=cry.encodeToHexNative(data.getBytes());
		System.out.println(ss);
		System.out.println(sss);
		System.out.println(s2);
	}
}
