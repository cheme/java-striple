package net.java.web3.striple.kind;

import net.java.web3.striple.IDDerivation;
import net.java.web3.striple.SignatureScheme;
import net.java.web3.striple.StripleData;
import net.java.web3.striple.StripleException;
import net.java.web3.striple.StripleKind;

public class Rsa2048Sha512 implements StripleKind {
	
    IDDerivation der = null;
    SignatureScheme sig =  null;
	public byte[] getKindId() {
		return StripleData.RSA2048SHA512KEY;
	}

	public Rsa2048Sha512() throws StripleException {
		super();
		der = new net.java.web3.striple.kind.idderivation.Sha512();
		sig = new net.java.web3.striple.kind.signature.Rsa2048();
	}

	public IDDerivation getIDDerivation() {
		return der;
	}

	public SignatureScheme getSignatureScheme() {
		return sig;
	}

}
