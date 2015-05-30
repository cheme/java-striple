package net.java.web3.striple.kind;

import net.java.web3.striple.IDDerivation;
import net.java.web3.striple.SignatureScheme;
import net.java.web3.striple.StripleData;
import net.java.web3.striple.StripleException;
import net.java.web3.striple.StripleKind;
import net.java.web3.striple.kind.idderivation.Identity;

public class PubRipemd implements StripleKind {
	
    IDDerivation der = new Identity();
    SignatureScheme sig =  null;
	public byte[] getKindId() {
		return StripleData.PUBRIPEMKEY;
	}

	public PubRipemd() throws StripleException {
		super();
		sig = new net.java.web3.striple.kind.signature.PubRipemd();
	}

	public IDDerivation getIDDerivation() {
		return der;
	}

	public SignatureScheme getSignatureScheme() {
		return sig;
	}

}
