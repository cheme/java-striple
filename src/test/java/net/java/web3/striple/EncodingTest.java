package net.java.web3.striple;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Random;

import net.java.web3.striple.kind.signature.PubKey;
import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

/**
 * Unit test for simple App.
 */
public class EncodingTest extends TestCase {
	/**
	 * Create the test case
	 *
	 * @param testName
	 *            name of the test case
	 */
	public EncodingTest(String testName) {
		super(testName);
	}

	/**
	 * @return the suite of tests being tested
	 */
	public static Test suite() {
		return new TestSuite(EncodingTest.class);
	}

	/**
	 * Check result of size encoding (jvm big endian and specific xtendsize enc)
	 */
	public void testEncodeSize() {

		assertTrue(Arrays.equals(StripleMethods.xtendsize(0, 0), new byte[0]));
		assertTrue(Arrays.equals(StripleMethods.xtendsize(0, 1),
				new byte[] { (byte) 0 }));
		assertTrue(Arrays.equals(StripleMethods.xtendsize(127, 1),
				new byte[] { (byte) 127 }));
		assertTrue(Arrays.equals(StripleMethods.xtendsize(128, 1), new byte[] {
				(byte) 129, 0x00, (byte) 128 }));
		assertTrue(Arrays.equals(StripleMethods.xtendsize(357, 2), new byte[] {
				(byte) 1, (byte) 101 }));
		assertTrue(Arrays.equals(StripleMethods.xtendsize(357, 1), new byte[] {
				(byte) 129, (byte) 1, (byte) 101 }));
		assertTrue(Arrays.equals(StripleMethods.xtendsize(357000, 1),
				new byte[] { (byte) 130, (byte) 5, (byte) 114, (byte) 136 }));

	}

	/**
	 * Check result of size decoding
	 */
	public void testDecodeSize() {
		byte[] input = new byte[] { (byte) 1, (byte) 2, (byte) 3, (byte) 4,
				(byte) 4 };
		assertEquals(StripleMethods.xtendsizedec(input, 3, 0)[0], 0);
		input = new byte[] { (byte) 1, (byte) 2, (byte) 3, (byte) 0, (byte) 4 };
		assertEquals(StripleMethods.xtendsizedec(input, 3, 1)[0], 0);
		input = new byte[] { (byte) 1, (byte) 2, (byte) 127, (byte) 0, (byte) 4 };
		assertEquals(StripleMethods.xtendsizedec(input, 2, 1)[0], 127);
		input = new byte[] { (byte) 1, (byte) 2, (byte) 129, (byte) 0,
				(byte) -128 };
		assertEquals(StripleMethods.xtendsizedec(input, 2, 1)[0], 128);
		input = new byte[] { (byte) 1, (byte) 2, (byte) 1, (byte) 101, (byte) 4 };
		assertEquals(StripleMethods.xtendsizedec(input, 2, 2)[0], 357);
		input = new byte[] { (byte) 1, (byte) 2, (byte) 129, (byte) 1,
				(byte) 101 };
		assertEquals(StripleMethods.xtendsizedec(input, 2, 1)[0], 357);
		input = new byte[] { (byte) 1, (byte) 2, (byte) 130, (byte) 5,
				(byte) 114, (byte) 136 };
		assertEquals(StripleMethods.xtendsizedec(input, 2, 1)[0], 357000);

		// overflow is same as 0 (bad)
		input = new byte[] { (byte) 1, (byte) 2, (byte) 130, (byte) 136,
				(byte) 114 };
		assertEquals(StripleMethods.xtendsizedec(input, 2, 1)[0], 0);

	}
	
	public void testReadWriteId() throws IOException {
		byte[] id1 = new byte[] { (byte) 1, (byte) 2, (byte) 3, (byte) 4,(byte)5};
		byte[] id2 = new byte[] { (byte) 11, (byte) 12, (byte) 13};
		ByteArrayOutputStream buff = new ByteArrayOutputStream();
		StripleMethods.pushId(id1, buff);
		StripleMethods.pushId(id2, buff);
		ByteBuffer b = ByteBuffer.wrap(buff.toByteArray());
		byte[] nid_1 = StripleMethods.readId(b);
		byte[] nid_2 = StripleMethods.readId(b);
		assertTrue(Arrays.equals(id1, nid_1));
		assertTrue(Arrays.equals(id2, nid_2));
		buff.close();
		
	}
	class ResolveToTestKind1 implements KindResolver {

		public StripleKind kindResolve(byte[] kindId, Striple from)
				throws StripleException {
			return new TestKind1();
		}
		
	}
    class TestKind1 implements StripleKind, IDDerivation, SignatureScheme {
       public byte[] getKindId() {
    	   return new byte[]{1,1,1};
       }
       public IDDerivation getIDDerivation() {
    	   return this;
       }
       public SignatureScheme getSignatureScheme() {
    	   return this;
       }
       public byte[] deriveID(byte[] sig) {
          // simply use signature as key
    	  return sig;
       }
       public boolean checkIDDerivation(byte[] sig, byte[] id) {
    	   return Arrays.equals(sig,id);
       }
       public byte[] signContent(PrivateKey pri, byte[] cont) {
    	   // Dummy just use pri
    	   return pri.getEncoded();
       }
       public boolean checkContent(PublicKey pub, byte[] cont, byte[] sig) {
	      // Dummy
    	   return !Arrays.equals(pub.getEncoded(),sig);
       }
       public KeyPair newKeyPair() {
    	   byte[] key = new byte[4];
    	   new Random().nextBytes(key);
    	   PubKey pk = new PubKey(key);
    	   return new KeyPair(pk,pk);
       }
	public PublicKey deserPubKey(byte[] key) {
		return new PubKey(key);
	}
	public PrivateKey deserPriKey(byte[] key) {
		return new PubKey(key);
	}
	public byte[] encodePrivateKey(PrivateKey privateKey) {
		return privateKey.getEncoded();
	}
	public byte[] encodePublicKey(PublicKey key) {
		return key.getEncoded();
	}
    }
    
	public void testStripleEncDec() throws IOException, StripleException {
		Random gen = new Random();
		byte[] commonId = new byte[4];
		gen.nextBytes(commonId);
		byte[] commonId2 = new byte[2];
		gen.nextBytes(commonId2);
		StripleImpl ori1 = new StripleImpl();
		// init with invalid values (no signing for usage with dummy kind
		ori1.kind = new TestKind1();
		ori1.contEnc = new byte[0];
		ori1.id = commonId;
		ori1.from = commonId2;
		ori1.sig = commonId.clone();
		ori1.about = new byte[0];
		ori1.key = new PubKey(new byte[]{0});
		ori1.contentids = new byte[][]{new byte[]{8,9}};
		ori1.content = new byte[0];
	
		byte[] encOri1 = ori1.stripleSer();
		
		StripleImpl decOri1 = StripleImpl.stripleDSer(encOri1,null, new ResolveToTestKind1());
		
		assertTrue(compareStriple(ori1,decOri1));
		
	}
	
    // for testing comparison (normally we only compare id of checked striple
	public static boolean compareStriple (Striple s1, Striple s2) {
		return (Arrays.equals(s1.getAbout(), s2.getAbout()) || s1.getAbout().length == 0 || s2.getAbout().length == 0)
				&& (s1.getKind().getClass() == s2.getKind().getClass())
				&& Arrays.equals(s1.getContEnc(), s2.getContEnc())
				&& Arrays.equals(s1.getContent(), s2.getContent())
				&& Arrays.deepEquals(s1.getContentIds(), s2.getContentIds())
				&& Arrays.equals(s1.getFrom(), s2.getFrom())
				&& Arrays.equals(s1.getId(), s2.getId())
				&& Arrays.equals(s1.getKey().getEncoded(), s2.getKey().getEncoded())
				&& (Arrays.equals(s1.getSig(), s2.getSig()) || s1.getSig().length == 0 || s2.getSig().length == 0)
				;
	}
	

}
