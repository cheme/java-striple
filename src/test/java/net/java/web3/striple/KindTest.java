package net.java.web3.striple;

import java.security.KeyPair;
import java.util.Arrays;
import java.util.Random;


import net.java.web3.striple.kind.PubRipemd;
import net.java.web3.striple.kind.PubSha512;
import net.java.web3.striple.kind.Rsa2048Sha512;
import junit.framework.TestCase;

public class KindTest extends TestCase {

	public void testRSA() throws StripleException {
		StripleKind kind = new Rsa2048Sha512();
/*		KeyPair kp = kind.getSignatureScheme().newKeyPair();
		assertEquals(true, true);*/
		stripleKindTest(kind, 256, false);
	}
    public void testPubSha512() throws StripleException {
		StripleKind kind = new PubSha512();
		stripleKindTest(kind, 64, true);
	}
    public void testPubSha256() throws StripleException {
		StripleKind kind = new PubSha512();
		stripleKindTest(kind, 32, true);
	}
    public void testPubRipemd() throws StripleException {
		StripleKind kind = new PubRipemd();
		stripleKindTest(kind, 20, true);
	}
	   
	private void stripleKindTest(StripleKind sk, int sigLength, boolean isPub) {
		uniqueKeyDer(sk.getIDDerivation(), sigLength);
		if (isPub) {
			pubSign(sk.getSignatureScheme());
		} else {
			priSign(sk.getSignatureScheme());
		}
	}

	private void uniqueKeyDer(IDDerivation der, int sigLength) {
		Random rng = new Random();
		assertTrue(sigLength > 0);
		byte[] sig1 = new byte[sigLength];
		byte[] sig2 = new byte[sigLength];
		byte[] sig3 = new byte[sigLength];
		rng.nextBytes(sig1);
		rng.nextBytes(sig2);
		rng.nextBytes(sig3);
		byte[] sigNull = new byte[0];
		if (sig1.equals(sig2) || sig1.equals(sig3)) {
			uniqueKeyDer(der, sigLength);
		}else{
			byte[] id1 = der.deriveID(sig1);
			byte[] id2 = der.deriveID(sig2);
			byte[] id3 = der.deriveID(sig3);
			byte[] idNull = der.deriveID(sigNull);
			assertFalse(id1.equals(id2));
			assertFalse(id3.equals(id2));
			// no info loss
			assertTrue(sig1.length >= id1.length);
			//null
			assertTrue(sigNull.length == idNull.length);
			
			assertTrue(der.checkIDDerivation(sig3, id3));
			
		}
	}

	private void pubSign(SignatureScheme sc) {
		KeyPair kp1 = sc.newKeyPair();
		KeyPair kp2 = sc.newKeyPair();
		byte[] cont1 = new byte[]{1,2,3,4};
		byte[] cont2 = new byte[0];
		byte[] sig1 = sc.signContent(kp1.getPrivate(), cont1);
		byte[] sig2 = sc.signContent(kp2.getPrivate(), cont2);
		
		
		assertFalse(Arrays.equals(kp1.getPublic().getEncoded(),kp2.getPublic().getEncoded()));
		
		assertTrue(Arrays.equals(kp1.getPrivate().getEncoded(),kp1.getPublic().getEncoded()));
		assertTrue(Arrays.equals(kp2.getPrivate().getEncoded(),kp2.getPublic().getEncoded()));
		
		assertTrue(sc.checkContent(kp1.getPublic(), cont1, sig1));
		assertFalse(sc.checkContent(kp2.getPublic(), cont1, sig1));
		assertFalse(sc.checkContent(kp2.getPublic(), cont1, sig2));
		assertTrue(sc.checkContent(kp2.getPublic(), cont2, sig2));
	
		assertTrue(Arrays.equals(sig1,sc.signContent(kp1.getPrivate(), cont1)));

	}

	private void priSign(SignatureScheme sc) {
		KeyPair kp1 = sc.newKeyPair();
		KeyPair kp2 = sc.newKeyPair();
		byte[] cont1 = new byte[]{1,2,3,4};
		byte[] cont2 = new byte[]{1,2,3,4,5};
		byte[] sig1 = sc.signContent(kp1.getPrivate(), cont1);
		byte[] sig2 = sc.signContent(kp2.getPrivate(), cont2);
		
		
		assertFalse(Arrays.equals(kp1.getPublic().getEncoded(),kp2.getPublic().getEncoded()));
		
		assertFalse(Arrays.equals(kp1.getPrivate().getEncoded(),kp1.getPublic().getEncoded()));
		
		assertFalse(sig1 == null);
		assertFalse(sig1.length == 0);
		
		assertTrue(sc.checkContent(kp1.getPublic(), cont1, sig1));
		assertTrue(sc.checkContent(kp2.getPublic(), cont2, sig2));
	
		assertTrue(sc.checkContent(kp1.getPublic(), cont1, sig1));
		assertFalse(sc.checkContent(kp2.getPublic(), cont1, sig1));
		assertFalse(sc.checkContent(kp1.getPublic(), cont1, new byte[]{2,3,6}));
		assertTrue(sc.checkContent(kp2.getPublic(), cont2, sig2));
	
	}

}
