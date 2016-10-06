package uc3m.jenarvaezg.dataprot1;

import java.util.Arrays;


public class Main {

	
	public static String byteArrayToHex(byte[] a) {
		   StringBuilder sb = new StringBuilder(a.length * 2);
		   for(byte b: a)
		      sb.append(String.format("%02x", b & 0xff));
		   return sb.toString();
		}
	
	
	public static void main(String[] args) throws Exception {
		int KEY_SIZE = 128 / 8;
		byte[] byteKey = new byte[KEY_SIZE];
		
		
		
		for(int i = 0; i < KEY_SIZE; i++){
			byteKey[i] = (byte) i;
		}
				
		
		SymmetricCipher s = new SymmetricCipher();
		byte[] ctext = s.encryptCBC("12345612345618u0hju34".getBytes(), byteKey);
		
		byte[] text = s.decryptCBC(ctext, byteKey);
		
		System.out.println(new String(text));
		
	}

}
