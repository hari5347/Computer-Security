import java.math.BigInteger;
import java.util.Arrays;
import java.util.Dictionary;
import java.util.Hashtable;
import javax.xml.bind.DatatypeConverter;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;


public class MITM {
	public static Dictionary<String, String> createKeyHashtable(String hexPlainText, String partOfKey1) throws Exception {
		/* 
		 * This method computes a hash table of (cyphertext, key) for key 1
		 * */
		
		// decode the hex encoded plaintext part of the (plaintext,cyphertext) pair
		// use it as the input to figure out the cyphertext corresponding to key 1
		byte[] plainText = DatatypeConverter.parseHexBinary(hexPlainText);
		
		//we use the partial bits we know from the key to define a binary key
		long longFormatKey1 = Long.parseLong(partOfKey1, 16); 
		String tentativeBinKey1 = String.format("%s", Long.toBinaryString(longFormatKey1)).replace(' ', '0');
		
		while (tentativeBinKey1.length() < partOfKey1.length()*4){
			tentativeBinKey1 = "0" + tentativeBinKey1;
		}


		// This hashtable will record all (cyphertext, key) pairs
		Dictionary<String, String> hashTable = new Hashtable();
		
		/*
		 * this for loop will try all possible values for key 1 and populate the hash table
		 */

		int iterlen = 56 - tentativeBinKey1.length();
		int iterexp = 1 << iterlen;

		for (int y = 0; y < iterexp; y++) {
			String binaryIntermediate = String.format("%s", Integer.toBinaryString(y)).replace(' ', '0');

			while (binaryIntermediate.length() < iterlen){
				binaryIntermediate = "0" + binaryIntermediate;
			}

			String possibleKey = binaryIntermediate + tentativeBinKey1;
			
			// store corresponding hex for output
			String firstKey = new BigInteger(possibleKey, 2).toString(16);
			
			//add the parity bits (so that every byte in the key has an odd number of "1" bits) in key 1
			for (int i = 0; i < 8; i++) {
				int numberOnes = 0;
				for (int x = i*7; x < (i*7)+7; x++) {
					if (possibleKey.charAt(x) == '1') 
						numberOnes++;
				}
				// add parity bit 1 if number of ones is even
				if ((numberOnes % 2) == 0)
					possibleKey = new StringBuilder(possibleKey).insert(((i+1)*8)-1, '1').toString();
				// add parity bit 0 if number of ones is odd 
				else
					possibleKey = new StringBuilder(possibleKey).insert(((i+1)*8)-1, '0').toString();
			} 
	
			// convert back to hex format
			String currentParityKey = new BigInteger(possibleKey, 2).toString(16);		
		
			// padd with 0s if key is not long enough before converting back to byte array
			while (currentParityKey.length() < 16){
				currentParityKey = "0" + currentParityKey;
			}
			byte[] keyBytes = DatatypeConverter.parseHexBinary(currentParityKey);
			
			if (keyBytes.length > 8) {
				keyBytes = Arrays.copyOfRange(keyBytes, 1, keyBytes.length);
			} 	
			
			// Create secret key in JCE format
			Cipher myDesCipher1 = Cipher.getInstance("DES/ECB/PKCS5Padding"); //to allow for any input size, use padding
			DESKeySpec saltForKeyFactory = new DESKeySpec(keyBytes);
			SecretKeyFactory secretDesKey1 = SecretKeyFactory.getInstance("DES");
			SecretKey key = secretDesKey1.generateSecret(saltForKeyFactory);
			
			// Find intermediate ciphertext and store result into table for use when looking for key2
			myDesCipher1.init(Cipher.ENCRYPT_MODE, key);
			byte[] intermediateCyphertext = myDesCipher1.doFinal(plainText);
			hashTable.put(new String(intermediateCyphertext), firstKey);
			
		}
		
		return hashTable;
	}
	public static void main(String[] args) throws Exception {
		/* 
		 * Given a pair of plaintext and cyphertext 
		 * as well a part of key1 and a part of key2. 
		 * recover key1 and key2 used to encrypt the plaintext
		 * into the cyphertext.
		 */

		//Input Format java MITM <plaintext> <ciphertext> <key1> <key2>

		// cypher text part of the plaintext, cyphertext pair
		byte[] cypherText = DatatypeConverter.parseHexBinary(args[1]);
		// part of the first key that was given in the lab question
		//String partOfKey1 = "1111111111";	
		String partOfKey1 = args[2];
		String partOfKey2 = args[3];	
		// call method createKeyHashtable to create a dictionnary of keys and corresponding cypher text for cypher 1
		Dictionary<String, String> hashTable = createKeyHashtable(args[0], partOfKey1);

		// try all possible keys for key 2 until I find one that produces a plain text that matches
		// something from the dictionnary, in which case return the corresponding key value
		//long longFormatKey2 = Long.parseLong("22222222", 16);
		long longFormatKey2 = Long.parseLong(partOfKey2, 16);
		String tentativeBinKey2 = String.format("%s", Long.toBinaryString(longFormatKey2)).replace(' ', '0');
		while (tentativeBinKey2.length() < partOfKey2.length()*4){
			tentativeBinKey2 = "0" + tentativeBinKey2;
		}
		
		int iterlen = 56 - tentativeBinKey2.length();
		int iterexp = 1 << iterlen;
		/*
		 * this for loop will try all possible values for key 2
		 */
		for (int y = 0; y < iterexp; y++) {
			String binaryIntermediate = String.format("%s", Integer.toBinaryString(y)).replace(' ', '0');
			
			while (binaryIntermediate.length() < iterlen){
				binaryIntermediate = "0" + binaryIntermediate;
			}

			String possibleKey = binaryIntermediate + tentativeBinKey2;
			
			// store corresponding hex for output
			String secondKey = new BigInteger(possibleKey, 2).toString(16);
	
			// add the parity bits (so that every byte in the key has an odd number of "1" bits) in key 1
			for (int i = 0; i < 8; i++) {
				int numberOnes = 0;
				for (int x = i*7; x < (i*7)+7; x++) {
					if (possibleKey.charAt(x) == '1') 
						numberOnes++;
				}
				// add parity bit 1 if number of ones is even
				if ((numberOnes % 2) == 0)
					possibleKey = new StringBuilder(possibleKey).insert(((i+1)*8)-1, '1').toString();
				// add parity bit 0 if number of ones is odd (we are good already)
				else
					possibleKey = new StringBuilder(possibleKey).insert(((i+1)*8)-1, '0').toString();
			} 

			// convert back to hex string representation
			String currentParityKey = new BigInteger(possibleKey, 2).toString(16);
	
			// padd with 0s if key is not long enough before converting back to byte array
			while (currentParityKey.length() < 16)
				currentParityKey = "0" + currentParityKey;
			byte[] keyBytes = DatatypeConverter.parseHexBinary(currentParityKey);
			
			if (keyBytes.length > 8) {
				keyBytes = Arrays.copyOfRange(keyBytes, 1, keyBytes.length);
			}
			
			
			 // Create secret key in JCE format
			Cipher myDesCipher2 = Cipher.getInstance("DES/ECB/NoPadding");
			DESKeySpec saltForKeyFactory = new DESKeySpec(keyBytes);
			SecretKeyFactory secretDesKey2 = SecretKeyFactory.getInstance("DES");
			SecretKey key = secretDesKey2.generateSecret(saltForKeyFactory);
	
			// Find intermediate ciphertext and store result into table for use when looking for key2
			myDesCipher2.init(Cipher.DECRYPT_MODE, key);
			byte[] middleCipher = myDesCipher2.doFinal(cypherText);
			
			// check if there is a key in the dictionnary with the same value 
			if (hashTable.get(new String(middleCipher)) != null) {
				System.out.println(hashTable.get(new String(middleCipher)) + " // " + secondKey);
				break;

			}
		}
	}
}

/*
Case 1: 
	Plaintext = 0123456789abcdef
	Ciphertext = 3057b90bd52bae5e1dc92a4ef6dd9775
	Key1 = 00000000000000
	Key2 = 11111111111111
Case 2:
	Plaintext = 48656c6c6f20576f726c6421
	Ciphertext = e89d327477bd5da2f84bcc6d016617d2
	Key1 = 1ab51111111111
	Key2 = 89fe3322222222
2^16 = 65536
2^20 = 1048576
2^24 = 16777216
2^28 = 268435456
*/