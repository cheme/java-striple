package net.java.web3.striple.kind.idderivation;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.security.Provider;

import net.java.web3.striple.StripleException;


public class Sha512 extends Digest {

	public Sha512() throws StripleException {
		super();
	}

	@Override
	String getMessageDigestName() {
		return "SHA-512";
	}

	@Override
	Provider getMessageDigestProvider() {
		return new BouncyCastleProvider();
	}

	

}
