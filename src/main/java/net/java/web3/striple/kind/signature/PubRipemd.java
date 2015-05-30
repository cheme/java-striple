package net.java.web3.striple.kind.signature;

import java.security.Provider;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import net.java.web3.striple.StripleException;

public class PubRipemd extends Public {

	public PubRipemd() throws StripleException {
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
