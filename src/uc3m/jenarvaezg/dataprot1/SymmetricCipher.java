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
	public void SymmetricCipher() {
	}
	
	
	
	private byte[][] splitIntoBlocks(byte[] input, int size){
		byte[][] blocks = new byte[size][BLOCK_SIZE];
		for(int i = 0; i < blocks.length; i++){
			blocks[i] = Arrays.copyOfRange(input, i*BLOCK_SIZE, i*BLOCK_SIZE + BLOCK_SIZE);
		}
		return blocks;
		
	}
	
	private byte[][] getPaddedBlocks(byte[] input){
		int diff;
		if(input.length % BLOCK_SIZE == 0){
			diff = BLOCK_SIZE;
		}else{
			diff = BLOCK_SIZE - (input.length % BLOCK_SIZE);
		}
		
		byte[] padding = new byte[diff];
		for(int i = 0 ; i < diff; i++){
			padding[i] = (byte)diff;
		}
		
		byte[] padded = new byte[input.length + padding.length];
		
		System.arraycopy(input, 0, padded, 0, input.length);
		System.arraycopy(padding, 0, padded, input.length, padding.length);
		
		byte[][] blocks = splitIntoBlocks(padded, padded.length/BLOCK_SIZE);//new byte[][BLOCK_SIZE];

		
		return blocks;
		
		
		
	}

    /*************************************************************************************/
	/* Method to encrypt using AES/CBC/PKCS5 */
    /*************************************************************************************/
	public byte[] encryptCBC (byte[] input, byte[] byteKey) throws Exception {
		
		byte[] ciphertext = null;	
		s = new SymmetricEncryption(byteKey);
		
		byte[][] blocks = getPaddedBlocks(input);
		
		int msgLength = BLOCK_SIZE * blocks.length;
		byte[] prev_ciphered = iv;
		
		ciphertext = new byte[msgLength];
		
		
		for(int i = 0; i < blocks.length; i++){
			byte[] xored = new byte[BLOCK_SIZE];
			for(int j = 0; j < BLOCK_SIZE; j++){	
				xored[j] = (byte) (blocks[i][j] ^ prev_ciphered[j]);
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
		
		byte[][] blocks = splitIntoBlocks(input, NBLOCKS);
		
		
		byte[] prev_ciphered = iv;
		byte[] padded = new byte[input.length];
		
		for(int i = 0; i < NBLOCKS; i++){
			
			byte[] deciphered = s.decryptBlock(blocks[i]);		
			
			byte[] xored = new byte[BLOCK_SIZE];
			for(int j = 0; j < BLOCK_SIZE; j++){	
				xored[j] = (byte) (deciphered[j] ^ prev_ciphered[j]);
			}
			prev_ciphered = blocks[i];
			System.arraycopy(xored, 0, padded, i * BLOCK_SIZE, BLOCK_SIZE);
		}
		
		finalplaintext = removePadding(padded);		
		
		return finalplaintext;
	}



	private byte[] removePadding(byte[] padded) throws Exception {
		int paddingLength = (int)padded[padded.length -1];
		for(int i = 0; i  < paddingLength; i++){
			if(padded[(padded.length - 1) - i] != paddingLength){
				throw new Exception("Padding incorrecto");
			}
			
		}
		byte[] unpadded = new byte[padded.length - paddingLength];
		System.arraycopy(padded, 0, unpadded, 0, padded.length - paddingLength);
		//System.out.println(Arrays.toString(a));
		return unpadded;
	}
	
}

