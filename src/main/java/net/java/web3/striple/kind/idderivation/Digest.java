package net.java.web3.striple.kind.idderivation;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.util.Arrays;

import net.java.web3.striple.IDDerivation;
import net.java.web3.striple.StripleException;
import net.java.web3.striple.StripleException.StripleExceptionType;

public abstract class Digest implements IDDerivation {
	MessageDigest md = null;

	abstract String getMessageDigestName();

	abstract Provider getMessageDigestProvider();

	public Digest() throws StripleException {
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

	public byte[] deriveID(byte[] sig) {
		if(sig.length == 0){
			return new byte[0];
		} else {
		    return md.digest(sig);
		}
	}

	public boolean checkIDDerivation(byte[] sig, byte[] id) {
		return Arrays.equals(this.deriveID(sig),id);
	}

}
