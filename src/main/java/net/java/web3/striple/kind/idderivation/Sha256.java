package net.java.web3.striple.kind.idderivation;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.security.Provider;

import net.java.web3.striple.StripleException;


public class Sha256 extends Digest {

	public Sha256() throws StripleException {
		super();
	}

	@Override
	String getMessageDigestName() {
		return "SHA-256";
	}

	@Override
	Provider getMessageDigestProvider() {
		return new BouncyCastleProvider();
	}

	

}
