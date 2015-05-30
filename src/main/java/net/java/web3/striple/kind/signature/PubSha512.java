package net.java.web3.striple.kind.signature;

import java.security.Provider;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import net.java.web3.striple.StripleException;

public class PubSha512 extends Public {

	public PubSha512() throws StripleException {
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
