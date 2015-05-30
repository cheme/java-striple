package net.java.web3.striple;

import java.io.IOException;
import java.security.KeyPair;
import java.security.PrivateKey;

public class OwnedStripleImpl extends StripleImpl implements OwnedStriple {
	PrivateKey privateKey;

	public PrivateKey getPrivateKey() {
		return privateKey;
	}
	
	
		
	public byte[] sign(byte[] tosig) {
		return this.getKind().getSignatureScheme().signContent(this.getPrivateKey(), tosig);
	};
		
		/**
	 * 
	 * @param contEnc
	 * @param from : the parent striple, if null from is ourselve (for root striple)
	 * @param about : about could be null (meaning its value is the same as from)
	 * @param contentids
	 * @param content
	 * @param kind
		 * @throws IOException 
		 * @throws StripleException 
	 */
	public OwnedStripleImpl(byte[] contEnc, OwnedStriple from, byte[] about,
			byte[][] contentids, byte[] content, StripleKind kind) throws IOException, StripleException {
		super();
		this.contEnc = contEnc;
		this.about = about;
		this.content = content;
		this.contentids = contentids;
		this.kind = kind;
		KeyPair keypair = kind.getSignatureScheme().newKeyPair();
		this.key = keypair.getPublic();
		this.privateKey = keypair.getPrivate();
		if (from == null) {
			// self signing
			this.sig = this.sign(this.getToSig());
    		this.id = kind.getIDDerivation().deriveID(this.sig);
		} else {
			// normal signing
			this.sig = StripleMethods.sign(from, this.getToSig());
    		this.id = from.getKind().getIDDerivation().deriveID(this.sig);
		}
		
		if (from == null) {
			this.from = this.id;
		} else {
			this.from = from.getId();
		}
		
	}
	/**
	 * Constructor to promote existing well formed striple to owned striple
	 * @param striple
	 * @param privatekey
	 * @throws StripleException 
	 */
	public OwnedStripleImpl(StripleImpl striple, byte[] privatekey) throws StripleException {
			super();
		this.contEnc = striple.contEnc;
		this.id = striple.id;
		this.from = striple.from;
		this.about = striple.about;
		this.content = striple.content;
		this.contentids = striple.contentids;
		this.sig = striple.sig;
		this.kind = striple.kind;
		this.key = striple.key;
		this.privateKey = kind.getSignatureScheme().deserPriKey(privatekey);
	}



	



	public byte[] encodePrivateKey() {
		return kind.getSignatureScheme().encodePrivateKey(this.privateKey);
	}
	


}
