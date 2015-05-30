package net.java.web3.striple.kind.signature;


import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import net.java.web3.striple.SignatureScheme;
import net.java.web3.striple.StripleException;
import net.java.web3.striple.StripleException.StripleExceptionType;

/**
 * basic private abstract class for java security implementation of Signature scheme
 * @author cheme
 *
 */
public abstract class Private implements SignatureScheme {
	MessageDigest md = null;
	Signature signat = null;
	
	abstract String getAlgo ();
	abstract int getAlgoSize ();
	abstract String getAlgoKg ();
	abstract String getDigest ();
	
	static KeyFactory keyFactory = null;
	static KeyPairGenerator gen = null;

	// static final String algo = "NonewithRSA";
	public Private() throws StripleException {
		super();

		try {
			if (gen == null) {
				gen = KeyPairGenerator.getInstance(this.getAlgoKg());
				gen.initialize(this.getAlgoSize());
			}
			if (keyFactory == null) {
    		   keyFactory = KeyFactory.getInstance(this.getAlgoKg());
			}
			Provider prov = new BouncyCastleProvider();
			md = MessageDigest.getInstance(this.getDigest(), prov);
			signat = Signature.getInstance(this.getAlgo(), prov);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			throw new StripleException(
					StripleExceptionType.KindImplementationNotFound,
					e.getMessage());
		}

	}

	public byte[] signContent(PrivateKey pri, byte[] cont) {
		
		byte[] tosign = (cont);
		//byte[] tosign = md.digest(cont);
		try {
			signat.initSign(pri);
		
		    signat.update(tosign);
		    return signat.sign();
		} catch (InvalidKeyException e) {
			// dirty exception mgmt
			e.printStackTrace();
			return new byte [0];
		} catch (SignatureException e) {
			// dirty exception mgmt
			e.printStackTrace();
			return new byte [0];
		}
	}

	public boolean checkContent(PublicKey pub, byte[] cont, byte[] sig) {
		byte[] tosign = (cont);
//		byte[] tosign = md.digest(cont);
		
	
		try {
		signat.initVerify(pub);
		signat.update(tosign);
		return signat.verify(sig);
		} catch (InvalidKeyException e) {
			// may not print
			e.printStackTrace();
			return false;
		} catch (SignatureException e) {
			// may not print
			e.printStackTrace();
			return false;
		}
	}

	public KeyPair newKeyPair() {
		return gen.generateKeyPair();
	}

	abstract public PublicKey deserPubKey(byte[] key) throws StripleException;
	
	abstract public PrivateKey deserPriKey(byte[] key) throws StripleException;


	
}
