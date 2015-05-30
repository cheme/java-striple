package net.java.web3.striple;

import java.io.IOException;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Random;

import net.java.web3.striple.kind.PubRipemd;
import net.java.web3.striple.kind.PubSha256;
import net.java.web3.striple.kind.PubSha512;
import net.java.web3.striple.kind.Rsa2048Sha512;
import junit.framework.TestCase;

public class ChainTest extends TestCase {
	
	public void testSelfChainingPubRip() throws IOException, StripleException {
		chainingTest(new PubRipemd(), new PubRipemd());
	}

	public void testSelfChainingRSA() throws IOException, StripleException {
		chainingTest(new Rsa2048Sha512(), new Rsa2048Sha512());
	}

	public void testMixChaining1() throws IOException, StripleException {
		chainingTest(new PubSha512(), new Rsa2048Sha512());
	}

	public void testMixChaining2() throws IOException, StripleException {
		chainingTest(new Rsa2048Sha512(), new PubSha256());
	}

	void chainingTest(StripleKind k1, StripleKind k2) throws IOException,
			StripleException {
		Random rng = new Random();
		byte[] contentenc = new byte[99];
		byte[] content1 = new byte[333];
		byte[] aboutson1 = new byte[9];
		byte[] aboutson2 = new byte[7];
		byte[] firstcontentidson1 = new byte[1];
		byte[] secondcontentidson1 = new byte[3];
		byte[] unknown = new byte[6];
		rng.nextBytes(contentenc);
		rng.nextBytes(content1);
		rng.nextBytes(aboutson1);
		rng.nextBytes(aboutson2);
		rng.nextBytes(firstcontentidson1);
		rng.nextBytes(secondcontentidson1);
		rng.nextBytes(unknown);

		OwnedStriple ownedRoot = new OwnedStripleImpl(contentenc, null, null,
				new byte[0][], content1, k1);
		Striple root = (Striple) ownedRoot;

		assertTrue(Arrays.equals(root.getKind().getKindId(), k1.getKindId()));
		assertTrue(Arrays.equals(root.getFrom(), root.getAbout()));
		assertTrue(root.check(root));
		OwnedStriple ownedSon1 = new OwnedStripleImpl(contentenc.clone(),
				ownedRoot, aboutson1, new byte[][] { firstcontentidson1,
						secondcontentidson1 }, new byte[0], k1);
		Striple son1 = (Striple) ownedSon1;

		assertTrue(son1.check(root));
		assertFalse(son1.check(son1));

		OwnedStriple ownedSon2 = new OwnedStripleImpl(contentenc.clone(),
				ownedRoot, aboutson2,
				new byte[][] { firstcontentidson1.clone(),
						secondcontentidson1.clone() }, content1.clone(), k2);
		Striple son2 = (Striple) ownedSon2;

		assertTrue(son2.check(root));
		assertFalse(son2.check(son1));
		assertFalse(son2.check(son2));

		OwnedStriple ownedSon21 = new OwnedStripleImpl(contentenc.clone(),
				ownedSon2, aboutson1,
				new byte[][] { firstcontentidson1.clone(),
						secondcontentidson1.clone() }, content1.clone(), k1);
		Striple son21 = (Striple) ownedSon21;
		assertTrue(son21.check(son2));
		OwnedStripleImpl ownedSon22 = new OwnedStripleImpl(contentenc.clone(),
				ownedSon2, aboutson1, new byte[][] { firstcontentidson1,
						secondcontentidson1 }, new byte[0], k2);
		StripleImpl son22 = (StripleImpl) ownedSon22;
		assertTrue(son22.check(son2));
		assertFalse(son22.check(root));
		OwnedStriple ownedSon22bis = new OwnedStripleImpl(contentenc.clone(),
				ownedSon2, aboutson1, new byte[][] { firstcontentidson1,
						secondcontentidson1 }, new byte[0], k2);
		Striple son22bis = (Striple) ownedSon22bis;
		assertFalse(EncodingTest.compareStriple(son22, son22bis));
		byte[] tmp = null;
		assertTrue(son22.check(son2));
		tmp = son22.from;
		son22.from = unknown;
		assertFalse(son22.check(son2));
		son22.from = tmp;
		assertTrue(son22.check(son2));
		tmp = son22.about;
		son22.about = unknown;
		assertFalse(son22.check(son2));
		son22.about = tmp;
		assertTrue(son22.check(son2));
		tmp = son22.content;
		son22.content = unknown;
		assertFalse(son22.check(son2));
		son22.content = tmp;
		assertTrue(son22.check(son2));
		byte[][] tmptmp = son22.contentids;
		son22.contentids = new byte[][] { unknown };
		assertFalse(son22.check(son2));
		son22.contentids = tmptmp;
		assertTrue(son22.check(son2));
		PublicKey tmpk = son22.key;
		son22.key = son21.getKey();
		assertFalse(son22.check(son2));
		son22.key = tmpk;
		assertTrue(son22.check(son2));
		tmp = son22.sig;
		son22.sig = unknown;
		assertFalse(son22.check(son2));
		son22.sig = tmp;
		assertTrue(son22.check(son2));
		tmp = son22.id;
		son22.id = unknown;
		assertFalse(son22.check(son2));
		son22.id = tmp;
		assertTrue(son22.check(son2));
		// encid impactless
		son22.contEnc = unknown;
		assertTrue(son22.check(son2));

	}

}
