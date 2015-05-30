package net.java.web3.striple.kind.signature;

import java.security.Provider;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import net.java.web3.striple.StripleException;

public class PubSha256 extends Public {

	public PubSha256() throws StripleException {
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
