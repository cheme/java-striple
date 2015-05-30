package net.java.web3.striple;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

public interface SignatureScheme {
	public byte[] signContent(PrivateKey pri, byte[] cont);

	public boolean checkContent(PublicKey pub, byte[] cont, byte[] sig);

	public KeyPair newKeyPair();

	public PublicKey deserPubKey(byte[] key) throws StripleException;

	public PrivateKey deserPriKey(byte[] key) throws StripleException;

	public byte[] encodePrivateKey(PrivateKey privateKey);

	public byte[] encodePublicKey(PublicKey key);
}
