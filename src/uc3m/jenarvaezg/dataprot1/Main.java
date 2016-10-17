package uc3m.jenarvaezg.dataprot1;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;


public class Main {

	
	private static String byteArrayToHex(byte[] a) {
		   StringBuilder sb = new StringBuilder(a.length * 2);
		   for(byte b: a)
		      sb.append(String.format("%02x", b & 0xff));
		   return sb.toString();
	}
	
	private static void writeToFile(byte[]bytes,  String path) throws FileNotFoundException{
		String hex = byteArrayToHex(bytes);
		FileOutputStream out = null;
		
		
		try {
			out = new FileOutputStream(new File(path));
			out.write(hex.getBytes());
		} catch (IOException e) {
			e.printStackTrace();
		}finally{
			if(out != null){
				try {
					out.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
		}
		
	}

	
	public static void main(String[] args) throws Exception {
		int KEY_SIZE = 128 / 8;
		byte[] byteKey = new byte[KEY_SIZE];	
		
		for(int i = 0; i < KEY_SIZE; i++){
			byteKey[i] = (byte) i;
		}
		
		writeToFile(byteKey, "keyfile.txt");
				
		
		SymmetricCipher s = new SymmetricCipher();
		byte[] ctext = s.encryptCBC("12345612345618u0hju34".getBytes(), byteKey);
		
		writeToFile(ctext, "ciphertext.txt");
		
		byte[] text = s.decryptCBC(ctext, byteKey);
		
		writeToFile(text, "deciphered.txt");
		
		System.out.println(new String(text));
		
	}

}
