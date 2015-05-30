package net.java.web3.striple.kind.signature;

import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.UUID;

import net.java.web3.striple.PublicSignature;
import net.java.web3.striple.StripleException;
import net.java.web3.striple.StripleException.StripleExceptionType;

/**
 * Public and private key are the same, a unique id, signing is just a crypto
 * digest including the key.
 * 
 * @author cheme
 *
 */
public abstract class Public implements PublicSignature {
	MessageDigest md = null;

	abstract String getMessageDigestName();

	abstract Provider getMessageDigestProvider();

	public Public() throws StripleException {
		super();
		try {
			md = MessageDigest.getInstance(this.getMessageDigestName(),
					this.getMessageDigestProvider());
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			throw new StripleException(
					StripleExceptionType.KindImplementationNotFound,
					e.getMessage());
		}

	}

	public byte[] signContent(PrivateKey prik, byte[] cont) {
		byte[] pri = prik.getEncoded();
		return dohash(pri, cont);
	}

	private byte[] dohash(byte[] key, byte[] cont) {
		byte[] all = new byte[key.length + cont.length];
		System.arraycopy(key, 0, all, 0, key.length);
		System.arraycopy(cont, 0, all, key.length, cont.length);
		return md.digest(all);
	}

	public boolean checkContent(PublicKey pubk, byte[] cont, byte[] sig) {
		byte[] pub = pubk.getEncoded();
		return Arrays.equals(sig,this.dohash(pub, cont));
	}

	public KeyPair newKeyPair() {
		UUID uuid = UUID.randomUUID();
		ByteBuffer buf = ByteBuffer.allocate(Long.SIZE / 4);
		buf.putLong(uuid.getLeastSignificantBits());
		buf.putLong(uuid.getMostSignificantBits());
		PubKey key = new PubKey(buf.array());
		return new KeyPair(key, key);
	}

    public PublicKey deserPubKey(byte[] key) {
    	return new PubKey(key);
    }
    public PrivateKey deserPriKey(byte[] key) {
    	return new PubKey(key);
    }
    
    public byte[] encodePrivateKey(PrivateKey privateKey) {
		return privateKey.getEncoded();
	}

	public byte[] encodePublicKey(PublicKey key) {
		return key.getEncoded();
	}
}
