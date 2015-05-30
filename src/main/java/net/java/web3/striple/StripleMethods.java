package net.java.web3.striple;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Arrays;

/**
 * Static methods for Striple manipulation (java 1.8 should be default interface
 * methods)
 * 
 * @author cheme
 *
 */
public class StripleMethods {

	static int INIT_TO_SIGBUFF_SIZE = 64;
	static int INIT_SERBUFF_SIZE = 128;
	static int ID_LENGTH_BYTES_ENC = 1;
	static int KEY_LENGTH_BYTES_ENC = 2;
	static int CONTENT_LENGTH_BYTES_ENC = 4;
	static int CONTIDS_LENGTH_BYTES_ENC = 1;
	static int SIG_LENGTH_BYTES_ENC = 4;

	static void pushId(byte[] id, ByteArrayOutputStream buff)
			throws IOException {
		buff.write(xtendsize(id.length, ID_LENGTH_BYTES_ENC));
		buff.write(id);
	}

	static byte[] readId(ByteBuffer buff) {
		System.out.print(buff.position());
		int[] sizederes = xtendsizedec(buff.array(), buff.position(),
				ID_LENGTH_BYTES_ENC);
		int size = sizederes[0];
		buff.position(sizederes[1]);
		System.out.println(buff.position());
		byte[] result = new byte[size];
		buff.get(result);
		return result;
	}

	public static byte[] xtendsize(int size, int nbbytes) {
		int maxval = maxvalue(nbbytes);
		int initbytes = nbbytes;
		int xtend = 0;
		// System.out.println("size :" + size + " - " + maxval);
		if (size > maxval) {
			// no loop one byte is enough for max int limit
			nbbytes = calcnbbytes(size);
			++xtend;
		}
		ByteBuffer bb = ByteBuffer.allocate(nbbytes + xtend);

		if (xtend > 0) {
			bb.put((byte) ((nbbytes - initbytes) ^ -128));
		}

		for (int i = 0; i < nbbytes; ++i) {
			bb.put((byte) (size >>> 8 * (nbbytes - i - 1)));
		}

		// for (int i = 0; i < nbbytes+xtend; ++i)
		// System.out.print(bb.array()[i] + ",");
		// System.out.println("---");

		return bb.array();
	}

	static int maxvalue(int nbbytes) {
		// TODO store possible result up to int max value (index of array).
		if (nbbytes < 1)
			return 0;
		else
			return (int) ((Math.pow(2, (nbbytes * 8)) - 1) / 2);
	}

	static int calcnbbytes(int val) {
		// TODO use same table as maxval
		for (int i = 1; i < 9; ++i) {
			if (val < (Math.pow(2, i * 8) - 1) / 2) {
				return i;
			}
		}
		;
		return 0;
	}

	// TODO change to Int ix and return only one int!!!!!
	public static int[] xtendsizedec(byte[] bytes, int ix, int size) {
		int adjix = 0;
		// System.out.println(bytes[ix]);
		while (bytes[ix] < 0) {
			adjix += (int) (bytes[ix] ^ -128);
			// System.out.println("adjix " + adjix + "!!");
			size += adjix;
			++ix;
		}
		ByteBuffer buff = ByteBuffer.allocate(4);
		for (int i = 0; i < 4; ++i) {
			if ((4 - i) > size) {
				buff.put((byte) 0);
			} else {
				int tmpix = ix + i - (4 - size);
				if (tmpix >= bytes.length)
					return new int[] { buff.getInt(0), ix + size };
				else
					buff.put(bytes[tmpix]);
			}
		}
		return new int[] { buff.getInt(0), ix + size };
	}

	static public byte[] getToSig(Striple striple) throws IOException {
		// ByteBuffer buf = ByteBuffer.allocate(INIT_TO_SIGBUFF_SIZE);
		ByteArrayOutputStream buf = new ByteArrayOutputStream();
		byte[] result = null;
		try {
			result = internalToSig(striple, buf);
		} finally {
			buf.close();
		}

		return result;
	};

	static private byte[] internalToSig(Striple striple,
			ByteArrayOutputStream buf) throws IOException {
		if (Arrays.equals(striple.getAbout(), striple.getId()))
			pushId(new byte[0], buf);
		else
			pushId(striple.getAbout(), buf);
		buf.write(xtendsize(striple.getKey().getEncoded().length,
				KEY_LENGTH_BYTES_ENC));
		buf.write(striple.encode_key());
		buf.write(xtendsize(striple.getContentIds().length,
				CONTIDS_LENGTH_BYTES_ENC));
		for (byte[] contentid : striple.getContentIds()) {
			pushId(contentid, buf);
		}
		buf.write(xtendsize(striple.getContent().length,
				CONTENT_LENGTH_BYTES_ENC));
		buf.write(striple.getContent());
		return buf.toByteArray();
	};

	static public boolean checkId(Striple from, Striple striple) {
		return from.getKind().getIDDerivation()
				.checkIDDerivation(striple.getSig(), striple.getId());
	};

	static public boolean checkSig(Striple from, Striple striple) {
		boolean result = false;
		if (Arrays.equals(from.getId(), striple.getFrom())) {
			byte[] toSig;
			try {
				toSig = StripleMethods.getToSig(striple);
				result = from.getKind().getSignatureScheme()
						.checkContent(from.getKey(), toSig, striple.getSig());

			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		return result;
	};

	static public boolean check(Striple from, Striple striple) {
		return checkId(from, striple) && checkSig(from, striple);
	};

	// TODO plug tochanel??
	static public byte[] stripleSer(Striple striple) throws IOException {
		// ByteBuffer buf = ByteBuffer.allocate(INIT_SERBUFF_SIZE);
		ByteArrayOutputStream buf = new ByteArrayOutputStream();
		byte[] result = null;
		try {
			pushId(striple.getKind().getKindId(), buf);
			pushId(striple.getContEnc(), buf);
			pushId(striple.getId(), buf);
			pushId(striple.getFrom(), buf);

			buf.write(xtendsize(striple.getSig().length, SIG_LENGTH_BYTES_ENC));
			buf.write(striple.getSig());

			internalToSig(striple, buf);

			result = buf.toByteArray();
		} finally {
			buf.close();
		}
		return result;
	};

	/**
	 * 
	 * @param bytes
	 * @param kind
	 *            , the kind of triple to use
	 * @param checkfrom
	 *            , if null no checking is done.
	 * @return
	 */
	static public StripleImpl stripleDSer(byte[] bytes, Striple checkfrom,
			KindResolver k) throws StripleException {
		return StripleImpl.stripleDSer(bytes, checkfrom, k);
	};

	static public byte[] sign(OwnedStriple from, byte[] tosig) {
		return from.getKind().getSignatureScheme()
				.signContent(from.getPrivateKey(), tosig);
	};

	static public byte[] encode_key(Striple s) {
		return s.getKind().getSignatureScheme().encodePublicKey(s.getKey());
	}

	static public boolean is_public(Striple s) {
		return s.getKind().getSignatureScheme() instanceof PublicSignature;
	};
	/*
	 * 
	 * 
	 * ErrorKind::DecodingError)) } else { Ok(StripleRef{ contentenc :
	 * contentenc, id : id, from : from, sig : sig, about : about, key : key,
	 * contentids : contentids, content : content,
	 * 
	 * phtype : PhantomData, }) } }
	 */

}
