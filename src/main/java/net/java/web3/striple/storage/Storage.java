package net.java.web3.striple.storage;

import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.ByteBuffer;
import java.nio.channels.SeekableByteChannel;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Iterator;
import java.util.Scanner;
import java.lang.Iterable;
import java.util.NoSuchElementException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import net.java.web3.striple.KindResolver;
import net.java.web3.striple.OwnedStriple;
import net.java.web3.striple.Striple;
import net.java.web3.striple.StripleException;
import net.java.web3.striple.StripleException.StripleExceptionType;
import net.java.web3.striple.storage.Pbkdf2EAS256.ReadCypherHeader;
import net.java.web3.striple.StripleImpl;
import net.java.web3.striple.StripleMethods;

/**
 * Methods to serialize to storage (file).
 *  TODO make a choice : here algebric type for read and instanceof for write
 * @author cheme
 *
 */
public class Storage {
	static final ByteBuffer NORMAL_TAG = ByteBuffer.wrap(new byte[] { 0 });
	static final int ENC_KEY_LENGTH = 2;
	static final int STRIPLE_KEY_LENGTH = 4;
	static final int CIPHER_TYPE_LENGTH = 1;

	/**
	 * 
	 * @param cyph
	 * @param striple
	 * @param owned
	 *            : owned striple private key or null if unknown
	 * @param dest
	 *            : //TODO could be byteoutputstream
	 * @throws IOException
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws InvalidAlgorithmParameterException
	 * @throws InvalidKeyException
	 * 
	 */
	public static void writeStriple(StorageCypher cyph, Striple striple,
			byte[] owned, SeekableByteChannel dest) throws IOException,
			InvalidKeyException, InvalidAlgorithmParameterException,
			IllegalBlockSizeException, BadPaddingException {
		// Tag as normal writing
		NORMAL_TAG.rewind();
		dest.write(NORMAL_TAG);
		if (owned == null || owned.length == 0) {
			dest.write(ByteBuffer.wrap(StripleMethods.xtendsize(0,
					ENC_KEY_LENGTH)));
		} else {
			byte[] enckey = cyph.encrypt(owned);
			dest.write(ByteBuffer.wrap(StripleMethods.xtendsize(enckey.length,
					ENC_KEY_LENGTH)));
			dest.write(ByteBuffer.wrap(enckey));
		}
		byte[] toSer = striple.stripleSer();
		dest.write(ByteBuffer.wrap(StripleMethods.xtendsize(toSer.length,
				STRIPLE_KEY_LENGTH)));
		dest.write(ByteBuffer.wrap(toSer));

	}

	/**
	 * tuple for striple and its privatekey (or null if not owned)
	 * 
	 * @author cheme
	 *
	 */
	public static class ReadStriple {
		public StripleImpl striple;
		public byte[] privateKey;
	}

	/**
	 * 
	 * @param cyph
	 * @param from
	 * @param k
	 *            : kind resolver get kind from read kind id and others striple
	 *            info
	 * @return a striple and a privatekey, class owned striple is used as a
	 *         commodity to replace a tuple. Therefore the striple is not own if
	 *         privatekey null and kind not public
	 * @throws IOException
	 * @throws StripleException
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws InvalidAlgorithmParameterException
	 * @throws InvalidKeyException
	 */
	public static ReadStriple readStriple(StorageCypher cyph,
			SeekableByteChannel from, KindResolver k) throws StripleException,
			IOException, InvalidKeyException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException,
			BadPaddingException {

		ByteBuffer onebyte = ByteBuffer.allocate(1);
		if (-1 == from.read(onebyte))
			throw new StripleException(StripleExceptionType.EmptyChannel,
					"end of channel");
		if (onebyte.array()[0] != NORMAL_TAG.array()[0]) {
			throw new StripleException(StripleExceptionType.InvalidInput,
					"unknown striple tag");
		}
		ByteBuffer buff = ByteBuffer.allocate(16);
		if (-1 == from.read(buff))
			throw new StripleException(StripleExceptionType.EmptyChannel,
					"end of channel");
		int[] r = StripleMethods.xtendsizedec(buff.array(), 0, ENC_KEY_LENGTH);
		int pklen = r[0];
		from.position(from.position() - 16 + r[1]);
		byte[] pk = null;
		if (pklen > 0) {
			ByteBuffer priv = ByteBuffer.allocate(pklen);
			if (-1 == from.read(priv))
				throw new StripleException(StripleExceptionType.EmptyChannel,
						"end of channel");
			pk = priv.array();
		}
		buff.rewind();
		if (-1 == from.read(buff))
			throw new StripleException(StripleExceptionType.EmptyChannel,
					"end of channel");
		r = StripleMethods.xtendsizedec(buff.array(), 0, STRIPLE_KEY_LENGTH);
		int stlen = r[0];
		from.position(from.position() - 16 + r[1]);
		ByteBuffer stbuff = ByteBuffer.allocate(stlen);
		if (-1 == from.read(stbuff))
			throw new StripleException(StripleExceptionType.EmptyChannel,
					"end of channel");
		StripleImpl st = StripleMethods.stripleDSer(stbuff.array(), null, k);
		ReadStriple result = new ReadStriple();
		result.striple = st;
		result.privateKey = cyph.decrypt(pk);
		return result;

	}

	// TODO switch to iterator (idem for read)
	public static void writeStripleFile(StorageCypher cyph, Iterable<Striple> striples,
			SeekableByteChannel dest) throws StripleException, IOException,
			InvalidKeyException, InvalidAlgorithmParameterException,
			IllegalBlockSizeException, BadPaddingException {
		dest.position(0);
		dest.write(ByteBuffer.wrap(cyph.getCypherHeader()));
		for (Striple st : striples) {
			if (st instanceof OwnedStriple) {
				PrivateKey pk = ((OwnedStriple) st).getPrivateKey();
				writeStriple(cyph, st, st.getKind().getSignatureScheme()
						.encodePrivateKey(pk), dest);
			} else {
				writeStriple(cyph, st, null, dest);

			}
		}
	}

	public static ReadStripleIterator initReadStripleIterator(
			SeekableByteChannel from, KindResolver k) throws IOException,
			NoSuchAlgorithmException, InvalidKeySpecException,
			NoSuchPaddingException, StripleException {
		ReadStripleIterator result = new ReadStripleIterator();
		result.from = from;
		result.k = k;
		from.position(0);
		// TODO plug a cipher resolver (for instance here stdin cypher is
		// useless in most cases) : do that after iter switch

		ByteBuffer buff = ByteBuffer.allocate(16);
		if (-1 == from.read(buff))
			throw new StripleException(StripleExceptionType.EmptyChannel,
					"end of channel");
		int[] r = StripleMethods.xtendsizedec(buff.array(), 0,
				CIPHER_TYPE_LENGTH);
		int citype = r[0];
		from.position(from.position() - 16 + r[1]);

		if (citype == 0) {
			result.cyph = new NoCypher();
		} else if (citype == 1) {
			Scanner scanin = null;
			String passphrase = null;
			try {
				System.out
						.println("Reading protected storage, please input passphrase ?");
				scanin = new Scanner(new InputStreamReader(System.in));
				passphrase = scanin.nextLine();
			} finally {
				if (scanin != null)
					scanin.close();
			}

			ReadCypherHeader head = Pbkdf2EAS256.readCypherHeader(from);
			result.cyph = new Pbkdf2EAS256(passphrase, head.iter, head.salt);
		} else {
			throw new StripleException(StripleExceptionType.InvalidInput,
					"Non supported cipher type");
		}

		return result;

	}

	public static class ReadStripleIterator implements Iterator<ReadStriple>,
			Iterable<ReadStriple> {
		ReadStriple next = null;
		StorageCypher cyph;
		SeekableByteChannel from;
		KindResolver k;

		public boolean hasNext() {
			boolean result = false;
			try {
				try {
					this.next = readStriple(cyph, from, k);
				} catch (InvalidKeyException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (InvalidAlgorithmParameterException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (IllegalBlockSizeException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (BadPaddingException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				result = true;
			} catch (IOException ex) {
				// TODO some log here or specialize iterator to add throw
				// exception
			} catch (StripleException e1) {
				// TODO some log here or specialize iterator to add throw
				// exception
			}
			return result;
		}

		public ReadStriple next() {
			ReadStriple result = null;
			if (next == null) {
				this.hasNext();
			}
			result = this.next;
			this.next = null;
			if (result == null) {
				throw new NoSuchElementException();
			}
			return result;
		}

		public void remove() {
			throw new UnsupportedOperationException();
		}

		public Iterator<ReadStriple> iterator() {
			return this;
		}

	}

}
