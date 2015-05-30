package net.java.web3.striple;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;


import net.java.web3.striple.storage.RemoveKey;
import net.java.web3.striple.storage.Storage;
import net.java.web3.striple.storage.Storage.ReadStriple;

/**
 * load base striple from a file Plus write them with different private key
 * encoding.
 * 
 * @author cheme
 *
 */
public class LoadBase {
	/**
	 * expected order of triples is X - root - libcat - libkind - kind -
	 * pubripemd - pubsha512 - pubsha256 - rsa2048Sha512 - ecdsaripemd160
	 * Unsigned version of : - kind - pubripemd - pubsha512 - pubsha256 -
	 * rsa2048Sha512 - ecdsaripemd160
	 * 
	 * 
	 * 
	 * @param args
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 * @throws NoSuchPaddingException
	 * @throws StripleException
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * @throws InvalidAlgorithmParameterException 
	 * @throws InvalidKeyException 
	 */
	public static void main(String[] args) throws IOException,
			NoSuchAlgorithmException, InvalidKeySpecException,
			NoSuchPaddingException, StripleException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		SeekableByteChannel datafile = null;
		SeekableByteChannel nosigfile = null;

		List<Striple> list = new ArrayList<Striple>(15);
		try {
			datafile = FileChannel.open(Paths.get("baseperm.data"),
					StandardOpenOption.READ);
			OwnedStriple[] striples = new OwnedStriple[15];
			Striple[] notownstriples = new Striple[15];
			int i = 0;
			for (ReadStriple st : Storage.initReadStripleIterator(datafile,
					new StripleData.LibStripleResolver())) {
				// TODO store only if private key here if kind is not public!!!
				if (st.striple.is_public()
						|| (st.privateKey != null && st.privateKey.length > 0)) {
					OwnedStriple os = new OwnedStripleImpl(st.striple,
							st.privateKey);
					striples[i] = os;
					list.add(os);
				} else {
					notownstriples[i] = st.striple;

					list.add(st.striple);
				}

				++i;
			}

			// Doing some check based upon knowned structure
			if (striples[0] != null) {
				OwnedStriple root = striples[0];
				System.out.println("doing root checking");

				// ////////// load pem exported

				// read private key DER file
				/*
				 * File pemfile = new File("pem64.pem"); DataInputStream dis =
				 * new DataInputStream(new FileInputStream(pemfile)); String
				 * base64 = dis.readLine(); // byte[] privKeyBytes = new
				 * byte[(int)pemfile.length()]; byte[] privKeyBytes =
				 * Base64.decode(base64); // dis.read(privKeyBytes);
				 * dis.close(); KeyFactory keyFactory =
				 * KeyFactory.getInstance("RSA");
				 * 
				 * // decode private key PKCS8EncodedKeySpec privSpec = new
				 * PKCS8EncodedKeySpec(privKeyBytes); RSAPrivateKey privKey =
				 * (RSAPrivateKey) keyFactory.generatePrivate(privSpec);
				 */
				// ///////////////

				byte[] cont = new byte[] { 56, 84, 8, 46, (byte) 250, 6, 8, 7 };
				// FileChannel sigfile =
				// FileChannel.open(Paths.get("sigjava.sig"),
				// StandardOpenOption.WRITE, StandardOpenOption.CREATE);
				byte[] sig = root.getKind().getSignatureScheme()
						.signContent(root.getPrivateKey(), cont);
				/*
				 * byte[] sig2 =
				 * root.getKind().getSignatureScheme().signContent(privKey,
				 * cont); sigfile.write(ByteBuffer.wrap(sig2)); sigfile.close();
				 */

				boolean sigcheckok = root.getKind().getSignatureScheme()
						.checkContent(root.getKey(), cont, sig);
				System.out.println("key is : " + sigcheckok);
				boolean checklibcat = striples[1].check(root);
				System.out.println("libcat root sign is : " + checklibcat);
				boolean checklibcont = striples[2].check(root);
				System.out.println("libcont root sign is : " + checklibcont);
			}

			// Doing some public check
			System.out.println("doing public checking");
			OwnedStriple pubkind = striples[9];
			boolean check11 = striples[11].check(pubkind);
			System.out.println("pubcheck 11  is : " + check11);
			boolean check12 = striples[12].check(pubkind);
			System.out.println("pubcheck 12 is : " + check12);

			nosigfile = FileChannel.open(Paths.get("base_nokey_java.data"),
					StandardOpenOption.WRITE, StandardOpenOption.CREATE);
			Storage.writeStripleFile(new RemoveKey(), list,nosigfile);

		} finally {
			if (datafile != null)
				datafile.close();
			if (nosigfile != null)
				nosigfile.close();
		}

		/*
		 * 
		 * /// load base file produced by generate example (privatekey clear).
		 * /// Plus write base file without password or with encrypted password.
		 * fn main() { // Doing some check based upon knowned structure
		 * 
		 * 
		 * // rewrite without private key for publishing
		 * 
		 * let mut datafile = File::create("./baseperm_nokey.data").unwrap(); //
		 * let refvec : Vec<(&AnyStriple,Option<&[u8]>)> =
		 * striples.iter().map(|i|(&i.0,i.1.as_ref().map(|o|&o[..]))).collect();
		 * let mut it =
		 * striples.iter().map(|i|(&i.0,i.1.as_ref().map(|o|&o[..]))); // let wr
		 * = write_striple_file(&RemoveKey, &mut refvec.iter(), &mut datafile);
		 * let wr = write_striple_file(&RemoveKey, &mut it, &mut datafile);
		 * 
		 * writepkbdf2(&striples);
		 * 
		 * print!("hello");
		 * 
		 * 
		 * }
		 */
	}

}
