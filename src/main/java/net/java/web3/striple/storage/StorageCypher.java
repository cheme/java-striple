package net.java.web3.striple.storage;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;

public interface StorageCypher {
	static final int HEADER_ID_VAL_LENGTH = 1;
	/**
	 * value identifying this cypher
	 */
	int getIdVal();
	/**
	 * Header of file (including id)
	 * @return header as bytes
	 */
	byte[] getCypherHeader ()throws IOException;
	
	
	byte[] encrypt (byte[] dec) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException;
;
	byte[] decrypt (byte[] enc) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException;


}
