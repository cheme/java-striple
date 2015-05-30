package net.java.web3.striple.storage;

import net.java.web3.striple.StripleException;
import net.java.web3.striple.StripleException.StripleExceptionType;
import net.java.web3.striple.StripleMethods;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SeekableByteChannel;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.SecureRandom;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;

public class Pbkdf2EAS256 implements StorageCypher {
	
	final static int ITERLENGTH = 2;
	final static int KEYLENGTHLENGTH = 2;
	final static int EAS256KEYLENGTH = 256;
	final static int EAS256BYTEKEYLENGTH = EAS256KEYLENGTH / 8;
	
	String pass;
	int iter;
	//useless for now
	int keylength;
	byte[] salt;
	Cipher cipher;
	Key key;
	
	public int getIdVal() {
		return 1;
	}
	
	
	/**
	 * null for salt to initialize new salt
	 * @param pass
	 * @param iter
	 * @param salt
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeySpecException 
	 * @throws NoSuchPaddingException 
	 */
	public Pbkdf2EAS256(String pass, int iter, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException {
		super();
		this.pass = pass;
		this.iter = iter;
		this.keylength = EAS256BYTEKEYLENGTH;
		if (salt == null) {
			SecureRandom.getSeed(EAS256BYTEKEYLENGTH);
	    }
		this.salt = salt;
		SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
		KeySpec keyspec = new PBEKeySpec(pass.toCharArray(), salt, iter, EAS256KEYLENGTH);
		this.key = factory.generateSecret(keyspec);
		this.cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
	}

	public byte[] getCypherHeader() throws IOException {
		ByteArrayOutputStream buf = new ByteArrayOutputStream();
		buf.write(StripleMethods.xtendsize(this.getIdVal(),HEADER_ID_VAL_LENGTH));
		buf.write(StripleMethods.xtendsize(this.iter,ITERLENGTH));
		buf.write(StripleMethods.xtendsize(this.keylength,KEYLENGTHLENGTH));
		buf.write(this.salt);
		return buf.toByteArray();
	}
	// struct class to use as a tuple see method readCypherHeader
    public static class ReadCypherHeader {
    	public int iter;
    	public int keylength;
    	public byte[] salt;
    }
    public static ReadCypherHeader readCypherHeader(SeekableByteChannel is) throws IOException, StripleException {
    	// buff for xtendsize over two bytes (limit of java int so using constant size buff)
    	ByteBuffer buff = ByteBuffer.allocate(16);
    	if (-1 == is.read(buff))
			throw new StripleException(StripleExceptionType.EmptyChannel, "end of channel");
    	int[] r = StripleMethods.xtendsizedec(buff.array(), 0, ITERLENGTH);
    	int iter = r[0];
    	is.position(is.position() - 16 + r[1]);
    	r = StripleMethods.xtendsizedec(buff.array(), 0, KEYLENGTHLENGTH);
     	int keylength = r[0];
    	is.position(is.position() - 16 + r[1]);
    	ByteBuffer salt = ByteBuffer.allocate(keylength);
    	if (-1 == is.read(salt))
			throw new StripleException(StripleExceptionType.EmptyChannel, "end of channel");
    	ReadCypherHeader result = new ReadCypherHeader();
    	result.iter = iter;
    	result.keylength = keylength;
    	result.salt = salt.array();
    	return result;
    	
    }
	
    public byte[] encrypt(byte[] dec) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		byte[] iv = SecureRandom.getSeed(this.cipher.getBlockSize());
    	IvParameterSpec ivspec = new IvParameterSpec(iv);
		this.cipher.init(Cipher.ENCRYPT_MODE, this.key, ivspec);
		byte[] iv2 = this.cipher.getIV();
	    System.out.println("iv gen : " + iv);
	    System.out.println("iv gen2 : " + iv2);

        byte[] enc = this.cipher.doFinal(dec);
		byte[] iv3 = this.cipher.getIV();
	    System.out.println("iv gen3 : " + iv3);
        ByteBuffer buff = ByteBuffer.allocate(iv.length + enc.length);
        buff.put(iv);
        buff.put(enc);
		return buff.array();
	}

	public byte[] decrypt(byte[] ivenc) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		byte[] iv = Arrays.copyOfRange(ivenc, 0, this.cipher.getBlockSize());
		byte[] enc = Arrays.copyOfRange(ivenc, this.cipher.getBlockSize(), ivenc.length);
		cipher.init(Cipher.DECRYPT_MODE, this.key, new IvParameterSpec(iv));
        return cipher.doFinal(enc);
	}

}
