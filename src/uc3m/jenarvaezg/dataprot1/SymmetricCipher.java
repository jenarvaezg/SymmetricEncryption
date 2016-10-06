package uc3m.jenarvaezg.dataprot1;

import java.io.FileDescriptor;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import javax.crypto.*;
import java.security.InvalidKeyException;
import java.util.Arrays;

public class SymmetricCipher {

	private static final int BLOCK_SIZE = 16;
	
	byte[] byteKey;
	SymmetricEncryption s;
	SymmetricEncryption d;
	
	// Initialization Vector (fixed)
	
	byte[] iv = new byte[] { (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54, 
		(byte)55, (byte)56, (byte)57, (byte)48, (byte)49, (byte)50, (byte)51, (byte)52,
		(byte)53, (byte)54};

    /*************************************************************************************/
	/* Constructor method */
    /*************************************************************************************/
	public  SymmetricCipher() {
	}
	
	
	/* Adds padding to input and returns input with padding at the end */
	private byte[] getPaddedInput(byte[] input){
		//length of padding
		int paddingLength = BLOCK_SIZE - (input.length % BLOCK_SIZE);
		
		//create padding array
		byte[] padding = new byte[paddingLength];
		for(int i = 0 ; i < paddingLength; i++){
			padding[i] = (byte)paddingLength;
		}
		
		//create array for sum of input and padding and put them together
		byte[] padded = new byte[input.length + padding.length];			
		System.arraycopy(input, 0, padded, 0, input.length);
		System.arraycopy(padding, 0, padded, input.length, padding.length);
		
		return padded;
		
		
	}
	
	/* Removes padding and throws Exception if padding not correct */
	private byte[] removePadding(byte[] padded) throws Exception {
		//last byte gives us padding length
		int paddingLength = (int)padded[padded.length -1];
		
		//check if padding is correct
		for(int i = 0; i  < paddingLength; i++){
			if(padded[(padded.length - 1) - i] != paddingLength){
				throw new Exception("Padding incorrecto");
			}
			
		}
		
		//return input without padding
		byte[] unpadded = Arrays.copyOfRange(padded, 0, padded.length - paddingLength);
		return unpadded;
	}

    /*************************************************************************************/
	/* Method to encrypt using AES/CBC/PKCS5 */
    /*************************************************************************************/
	public byte[] encryptCBC (byte[] input, byte[] byteKey) throws Exception {

		s = new SymmetricEncryption(byteKey);

		byte[] padded = getPaddedInput(input);
		byte[] ciphertext = new byte[padded.length];		
		
		byte[] prev_ciphered = iv;
		for(int i = 0; i < padded.length / BLOCK_SIZE; i++){
			byte[] xored = new byte[BLOCK_SIZE];
			for(int j = 0; j < BLOCK_SIZE; j++){	
				xored[j] = (byte) (padded[i*BLOCK_SIZE + j] ^ prev_ciphered[j]);
			}
			prev_ciphered = s.encryptBlock(xored);
			
			System.arraycopy(prev_ciphered, 0, ciphertext, i * BLOCK_SIZE, BLOCK_SIZE);
		}
		
		return ciphertext;
	}
	
	/*************************************************************************************/
	/* Method to decrypt using AES/CBC/PKCS5 */
    /*************************************************************************************/
	
	
	public byte[] decryptCBC (byte[] input, byte[] byteKey) throws Exception {
	
		
		byte [] finalplaintext = null;
		
		int NBLOCKS = input.length / BLOCK_SIZE;		
		
		byte[] prev_ciphered = iv;
		byte[] padded = new byte[input.length];
		
		for(int i = 0; i < NBLOCKS; i++){
			byte[] block = Arrays.copyOfRange(input, i*BLOCK_SIZE, i*BLOCK_SIZE + BLOCK_SIZE);
			byte[] deciphered = s.decryptBlock(block);
			
			byte[] xored = new byte[BLOCK_SIZE];
			for(int j = 0; j < BLOCK_SIZE; j++){	
				xored[j] = (byte) (deciphered[j] ^ prev_ciphered[j]);
			}
			prev_ciphered = block;
			System.arraycopy(xored, 0, padded, i * BLOCK_SIZE, BLOCK_SIZE);
		}
		
		finalplaintext = removePadding(padded);		
		
		return finalplaintext;
	}




	
}

