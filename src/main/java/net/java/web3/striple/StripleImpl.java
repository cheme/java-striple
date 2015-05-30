package net.java.web3.striple;

import java.nio.ByteBuffer;
import java.security.PublicKey;
import java.util.Arrays;

import net.java.web3.striple.StripleException.StripleExceptionType;

public class StripleImpl extends AbstractStriple {
	protected byte[] contEnc;
	protected byte[] id;
	protected byte[] from;
	protected byte[] about;
	protected byte[] content;
	protected byte[][] contentids;
	protected PublicKey key;
	protected byte[] sig;
	protected StripleKind kind;

	public byte[] getId() {
		return id;
	}

	public byte[] getFrom() {
		return from;
	}

	public byte[] getAbout() {
		if (about == null || about.length == 0) {
			return id;
		} else {
		    return about;
		}
	}

	public byte[] getContent() {
		return content;
	}

	public byte[][] getContentIds() {
		return contentids;
	}

	public PublicKey getKey() {
		return key;
	}

	public byte[] getSig() {
		return sig;
	}

	public StripleKind getKind() {
		return kind;
	}

	public byte[] getContEnc() {
		return contEnc;
	}
	/**
	 * 
	 * @param bytes
	 * @param kind
	 *            , the kind of triple to use
	 * @param checkfrom
	 *            , if null no checking is done.
	 * @return
	 */
	static public StripleImpl stripleDSer(byte[] bytes, 
			Striple checkfrom,
			KindResolver k) throws StripleException {
		ByteBuffer buff = ByteBuffer.wrap(bytes);
		int[] tmp = null;
		byte[] algoenc = StripleMethods.readId(buff);
		byte[] contentenc = StripleMethods.readId(buff);
		byte[] id = StripleMethods.readId(buff);
		byte[] from = StripleMethods.readId(buff);
		tmp = StripleMethods.xtendsizedec(bytes, buff.position(), StripleMethods.SIG_LENGTH_BYTES_ENC);
		buff.position(tmp[1]);
		byte[] sig = null;
		// test if identity id derive
		if (tmp[0] == 0) {
			sig = id;
		} else {
			sig = new byte[tmp[0]];
			buff.get(sig);
		}

		int startcontent = buff.position();

		byte[] about = StripleMethods.readId(buff);
		if (about.length == 0)
			about = id;
		
		tmp = StripleMethods.xtendsizedec(bytes, buff.position(), StripleMethods.KEY_LENGTH_BYTES_ENC);
		buff.position(tmp[1]);
		byte[] key = new byte[tmp[0]];
		buff.get(key);
		tmp = StripleMethods.xtendsizedec(bytes, buff.position(), StripleMethods.CONTIDS_LENGTH_BYTES_ENC);
		buff.position(tmp[1]);
		byte[][] contentids = new byte[tmp[0]][];
		for (int i=0;i<tmp[0];++i) {
			contentids[i] = StripleMethods.readId(buff);
		}
		
		tmp = StripleMethods.xtendsizedec(bytes, buff.position(), StripleMethods.CONTENT_LENGTH_BYTES_ENC);
		buff.position(tmp[1]);
		byte[] content = new byte[tmp[0]];
		buff.get(content);
		
		if (buff.position() != buff.capacity()){
			throw new StripleException(StripleExceptionType.DecodingError,
					"Mismatch size of striple");
	
		}
	
		if (checkfrom != null) {
			if (!Arrays.equals(checkfrom.getId(), id))
		  	throw new StripleException(StripleExceptionType.UnexpectedStriple,
					"Unexpected from id");
			buff.position(startcontent);
			byte[] tosign = buff.slice().array();
			if (!(checkfrom.getKind().getIDDerivation().checkIDDerivation(sig, id)
			&& checkfrom.getKind().getSignatureScheme().checkContent(checkfrom.getKey(), tosign, sig))){
			  	throw new StripleException(StripleExceptionType.UnexpectedStriple,
					"Invalid signature or key derivation");
			};
		}
		if (id.length == 0 || from.length == 0 || (contentids.length == 0 && content.length ==0)) {
				  	throw new StripleException(StripleExceptionType.DecodingError,
					"Invalid striple decoding");
		}
		StripleImpl res = new StripleImpl();
		res.contEnc = contentenc;
		res.id = id;
		res.from = from;
		res.about = about;
		res.content = content;
		res.contentids = contentids;
		res.sig = sig;
		StripleKind kind = k.kindResolve(algoenc, res);
		res.key = kind.getSignatureScheme().deserPubKey(key);
		res.kind = kind;
		return res;
	}

	protected StripleImpl() {
	}

	
	
    
    


}
