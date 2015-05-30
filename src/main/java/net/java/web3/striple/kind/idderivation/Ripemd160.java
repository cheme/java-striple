package net.java.web3.striple.kind.idderivation;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.security.Provider;

import net.java.web3.striple.StripleException;


public class Ripemd160 extends Digest {

	public Ripemd160() throws StripleException {
		super();
	}

	@Override
	String getMessageDigestName() {
		return "RipeMD160";
	}

	@Override
	Provider getMessageDigestProvider() {
		return new BouncyCastleProvider();
	}

	

}
