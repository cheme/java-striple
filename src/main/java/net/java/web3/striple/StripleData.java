package net.java.web3.striple;

import java.util.Arrays;

import net.java.web3.striple.StripleException.StripleExceptionType;
import net.java.web3.striple.kind.PubRipemd;
import net.java.web3.striple.kind.PubSha256;
import net.java.web3.striple.kind.PubSha512;
import net.java.web3.striple.kind.Rsa2048Sha512;

	


/**
 * Hardcoded striple to use.
 * TODO loading from conf (with varenv to load multiple files)
 * @author cheme
 *
 */
public class StripleData {
	public static byte[] PUBRIPEMKEY= new byte [] {(byte)131,(byte) 158,(byte) 16,(byte) 201,(byte) 240,(byte) 160,(byte) 172,(byte) 224,(byte) 207,(byte) 159,(byte) 116,(byte) 31,(byte) 191,(byte) 198,(byte) 192,(byte) 43,(byte) 78,(byte) 171,(byte) 24,(byte) 180,(byte) 183,(byte) 201,(byte) 237,(byte) 71,(byte) 217,(byte) 232,(byte) 249,(byte) 144,(byte) 77,(byte) 225,(byte) 41,(byte) 10,(byte) 157,(byte) 59,(byte) 145,(byte) 101,(byte) 235,(byte) 154,(byte) 95,(byte) 136,(byte) 216,(byte) 72,(byte) 65,(byte) 99,(byte) 200,(byte) 52,(byte) 20,(byte) 120,(byte) 20,(byte) 65,(byte) 60,(byte) 84,(byte) 178,(byte) 127,(byte) 141,(byte) 106,(byte) 196,(byte) 126,(byte) 36,(byte) 195,(byte) 88,(byte) 242,(byte) 123,(byte) 93};
	public static byte[] PUBSHA512KEY = new byte[] {(byte)171,(byte) 21,(byte) 71,(byte) 31,(byte) 182,(byte) 64,(byte) 250,(byte) 16,(byte) 97,(byte) 68,(byte) 201,(byte) 98,(byte) 227,(byte) 190,(byte) 62,(byte) 74,(byte) 19,(byte) 93,(byte) 165,(byte) 98,(byte) 118,(byte) 17,(byte) 189,(byte) 93,(byte) 93,(byte) 128,(byte) 2,(byte) 126,(byte) 121,(byte) 255,(byte) 44,(byte) 202,(byte) 109,(byte) 183,(byte) 159,(byte) 127,(byte) 200,(byte) 184,(byte) 75,(byte) 89,(byte) 188,(byte) 66,(byte) 223,(byte) 217,(byte) 251,(byte) 123,(byte) 187,(byte) 172,(byte) 119,(byte) 204,(byte) 150,(byte) 104,(byte) 140,(byte) 214,(byte) 164,(byte) 227,(byte) 190,(byte) 95,(byte) 242,(byte) 145,(byte) 178,(byte) 83,(byte) 202,(byte) 95};
	public static byte[] PUBSHA256KEY = new byte[] {(byte)25,(byte) 10,(byte) 108,(byte) 202,(byte) 192,(byte) 185,(byte) 24,(byte) 238,(byte) 203,(byte) 196,(byte) 34,(byte) 198,(byte) 65,(byte) 244,(byte) 12,(byte) 135,(byte) 0,(byte) 175,(byte) 255,(byte) 53,(byte) 191,(byte) 128,(byte) 220,(byte) 177,(byte) 12,(byte) 83,(byte) 215,(byte) 169,(byte) 237,(byte) 31,(byte) 193,(byte) 203,(byte) 159,(byte) 152,(byte) 230,(byte) 105,(byte) 40,(byte) 178,(byte) 23,(byte) 238,(byte) 14,(byte) 114,(byte) 101,(byte) 182,(byte) 85,(byte) 115,(byte) 215,(byte) 9,(byte) 160,(byte) 254,(byte) 112,(byte) 100,(byte) 152,(byte) 114,(byte) 130,(byte) 217,(byte) 192,(byte) 193,(byte) 141,(byte) 128,(byte) 184,(byte) 153,(byte) 37,(byte) 171};
	public static byte[] RSA2048SHA512KEY = new byte[] {(byte)216,(byte) 233,(byte) 21,(byte) 81,(byte) 76,(byte) 58,(byte) 81,(byte) 215,(byte) 56,(byte) 16,(byte) 193,(byte) 244,(byte) 39,(byte) 156,(byte) 13,(byte) 33,(byte) 215,(byte) 67,(byte) 79,(byte) 130,(byte) 179,(byte) 245,(byte) 104,(byte) 24,(byte) 45,(byte) 6,(byte) 197,(byte) 51,(byte) 89,(byte) 66,(byte) 147,(byte) 57,(byte) 18,(byte) 171,(byte) 207,(byte) 243,(byte) 198,(byte) 248,(byte) 145,(byte) 190,(byte) 68,(byte) 149,(byte) 44,(byte) 203,(byte) 146,(byte) 155,(byte) 30,(byte) 132,(byte) 229,(byte) 228,(byte) 93,(byte) 184,(byte) 101,(byte) 10,(byte) 52,(byte) 27,(byte) 177,(byte) 20,(byte) 145,(byte) 216,(byte) 4,(byte) 53,(byte) 173,(byte) 153};
	public static byte[] ECDSARIPEMD160KEY = new byte[] {(byte)106,(byte) 59,(byte) 17,(byte) 211,(byte) 187,(byte) 4,(byte) 5,(byte) 150,(byte) 249,(byte) 143,(byte) 65,(byte) 107,(byte) 199,(byte) 36,(byte) 186,(byte) 16,(byte) 10,(byte) 72,(byte) 61,(byte) 176,(byte) 187,(byte) 131,(byte) 109,(byte) 196,(byte) 84,(byte) 250,(byte) 254,(byte) 2,(byte) 23,(byte) 225,(byte) 202,(byte) 231,(byte) 84,(byte) 82,(byte) 180,(byte) 121,(byte) 96,(byte) 203,(byte) 190,(byte) 186,(byte) 171,(byte) 131,(byte) 166,(byte) 157,(byte) 190,(byte) 215,(byte) 205,(byte) 130,(byte) 247,(byte) 240,(byte) 116,(byte) 81,(byte) 29,(byte) 252,(byte) 49,(byte) 137,(byte) 134,(byte) 232,(byte) 118,(byte) 52,(byte) 61,(byte) 131,(byte) 127,(byte) 2};
	/**
	 * A kind resolver looking only if ID are those known by the lib.
	 * 
	 * @author cheme
	 *
	 */
	public static class LibStripleResolver implements KindResolver {

		public StripleKind kindResolve(byte[] kindId, Striple from)
				throws StripleException {
			StripleKind kind = null;
			// TODO use a map where loaded new kind also
			if (kind == null && Arrays.equals(kindId, PUBRIPEMKEY)) {
				kind = new PubRipemd();
		    }
			if (kind == null && Arrays.equals(kindId, PUBSHA512KEY)) {
				kind = new PubSha512();
		    }
			if (kind == null && Arrays.equals(kindId, PUBSHA256KEY)) {
				kind = new PubSha256();
		    }
			if (kind == null && Arrays.equals(kindId, RSA2048SHA512KEY)) {
				kind = new Rsa2048Sha512();
		    }
			if (kind == null && Arrays.equals(kindId, ECDSARIPEMD160KEY)) {
					throw new StripleException(StripleExceptionType.UnexpectedStriple,
					"TODO java implementation for ecdsaripemd160 kind!!");
		
		    }
			
			if (kind == null) {
		    	throw new StripleException(StripleExceptionType.UnexpectedStriple,
					"Wrong algo encoding received");
			}

			return kind;
		}
		
	}
}
