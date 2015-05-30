package net.java.web3.striple.kind.signature;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.RSAPrivateKeyStructure;

import net.java.web3.striple.StripleException;
import net.java.web3.striple.StripleException.StripleExceptionType;

/**
 * Public and private key are the same, a unique id, signing is just a crypto
 * digest including the key.
 *  
 *  like openssl pkeyutl -sign -in tosign -inkey pem.pem -pkeyopt digest:sha512 -out cmd.sig
 *  over a first sha512 (see private for first sha)
 * @author cheme
 *
 */
public class Rsa2048 extends Private {

	static final String ALGO = "SHA512withRSA";
//	static final String ALGO = "RSA";
	static final String ALGOKG = "RSA";
	static final String DIGEST = "SHA-512";
	static final int ALGOSIZE = 2048;

	@Override
	String getAlgo() {
		return ALGO;
	}

	@Override
	int getAlgoSize() {
		return ALGOSIZE;
	}

	@Override
	String getAlgoKg() {
		return ALGOKG;
	}

	@Override
	String getDigest() {
		return DIGEST;
	}

	public Rsa2048() throws StripleException {
		super();
	}

	public PublicKey deserPubKey(byte[] key) throws StripleException {
		X509EncodedKeySpec kspec = new X509EncodedKeySpec(key);
		try {
			return keyFactory.generatePublic(kspec);
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
			throw new StripleException(StripleExceptionType.DecodingError,
					e.getMessage());
		}
	}

	public PrivateKey deserPriKey(byte[] key) throws StripleException {
		// String test = key.toString();
		// PKCS8EncodedKeySpec kspec= new PKCS8EncodedKeySpec(key);
		// RSAPrivateCrtKeySpec kspec = new RSAPrivateCrtKeySpec();
		try {
			ASN1Sequence as = (ASN1Sequence) ASN1Sequence.fromByteArray(key);
			RSAPrivateKeyStructure struct = new RSAPrivateKeyStructure(as);
			RSAPrivateCrtKeySpec spec = new RSAPrivateCrtKeySpec(
					struct.getModulus(), struct.getPublicExponent(),
					struct.getPrivateExponent(), struct.getPrime1(),
					struct.getPrime2(), struct.getExponent1(),
					struct.getExponent2(), struct.getCoefficient());

			return keyFactory.generatePrivate(spec);
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
			throw new StripleException(StripleExceptionType.DecodingError,
					e.getMessage());
		} catch (IOException e) {
			e.printStackTrace();
			throw new StripleException(StripleExceptionType.DecodingError,
					e.getMessage());
		}
	}

	public byte[] encodePrivateKey(PrivateKey privateKey) {
		byte[] result = null;
		PrivateKeyInfo pki = PrivateKeyInfo
				.getInstance(privateKey.getEncoded());
		RSAPrivateKeyStructure pkcs1Key = RSAPrivateKeyStructure
				.getInstance(pki.getPrivateKey());
		try {
			result = pkcs1Key.getEncoded();
		} catch (IOException e) {
			e.printStackTrace();
		}
		return result;
	}

	public byte[] encodePublicKey(PublicKey key) {
		return key.getEncoded();
	}

}
