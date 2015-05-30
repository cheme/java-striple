package net.java.web3.striple.kind.signature;

import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Dummy public key over random bytes for public signing scheme
 * @author cheme
 *
 */
public class PubKey implements PublicKey, PrivateKey {
	/**
	 * 
	 */
	private static final long serialVersionUID = -4050790939404478441L;
	
	public PubKey(byte[] content) {
		super();
		this.content = content;
	}

	byte[] content;

	public String getAlgorithm() {
		return "StriplePublic";
	}

	public byte[] getEncoded() {
		return content;
	}

	public String getFormat() {
		return "StriplePublic";
	}

}
