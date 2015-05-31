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
	public static byte[] PUBRIPEMKEY= new byte [] {(byte)128, (byte)136, (byte)74, (byte)231, (byte)134, (byte)102, (byte)111, (byte)168, (byte)123, (byte)102, (byte)154, (byte)32, (byte)53, (byte)15, (byte)250, (byte)179, (byte)54, (byte)171, (byte)54, (byte)65, (byte)184, (byte)110, (byte)152, (byte)28, (byte)84, (byte)80, (byte)17, (byte)123, (byte)79, (byte)150, (byte)127, (byte)183, (byte)17, (byte)70, (byte)236, (byte)170, (byte)236, (byte)87, (byte)252, (byte)42, (byte)15, (byte)88, (byte)218, (byte)133, (byte)203, (byte)53, (byte)151, (byte)68, (byte)175, (byte)32, (byte)221, (byte)4, (byte)68, (byte)51, (byte)208, (byte)114, (byte)235, (byte)117, (byte)1, (byte)245, (byte)2, (byte)96, (byte)25, (byte)1};
	public static byte[] PUBSHA512KEY = new byte[] {88, (byte)245, (byte)150, (byte)98, (byte)43, (byte)39, (byte)41, (byte)192, (byte)133, (byte)100, (byte)60, (byte)217, (byte)26, (byte)84, (byte)198, (byte)156, (byte)232, (byte)249, (byte)118, (byte)12, (byte)248, (byte)27, (byte)218, (byte)227, (byte)234, (byte)2, (byte)180, (byte)129, (byte)35, (byte)11, (byte)121, (byte)103, (byte)2, (byte)40, (byte)60, (byte)248, (byte)53, (byte)200, (byte)121, (byte)22, (byte)18, (byte)197, (byte)194, (byte)107, (byte)114, (byte)17, (byte)210, (byte)100, (byte)36, (byte)109, (byte)179, (byte)73, (byte)84, (byte)66, (byte)27, (byte)251, (byte)16, (byte)49, (byte)253, (byte)205, (byte)61, (byte)159, (byte)64, (byte)108};
	public static byte[] PUBSHA256KEY = new byte[] {122, (byte)43, (byte)209, (byte)100, (byte)41, (byte)177, (byte)153, (byte)216, (byte)58, (byte)115, (byte)121, (byte)167, (byte)37, (byte)62, (byte)227, (byte)206, (byte)8, (byte)69, (byte)210, (byte)159, (byte)206, (byte)196, (byte)58, (byte)71, (byte)132, (byte)174, (byte)233, (byte)151, (byte)91, (byte)190, (byte)132, (byte)30, (byte)188, (byte)200, (byte)108, (byte)148, (byte)169, (byte)99, (byte)23, (byte)191, (byte)46, (byte)23, (byte)9, (byte)239, (byte)236, (byte)73, (byte)179, (byte)54, (byte)223, (byte)209, (byte)109, (byte)193, (byte)72, (byte)243, (byte)227, (byte)81, (byte)209, (byte)194, (byte)155, (byte)61, (byte)67, (byte)170, (byte)43, (byte)224};
	public static byte[] RSA2048SHA512KEY = new byte[] {86, (byte)139, (byte)16, (byte)216, (byte)242, (byte)57, (byte)38, (byte)17, (byte)66, (byte)247, (byte)128, (byte)160, (byte)222, (byte)3, (byte)60, (byte)76, (byte)108, (byte)12, (byte)64, (byte)158, (byte)237, (byte)232, (byte)35, (byte)207, (byte)98, (byte)23, (byte)159, (byte)236, (byte)165, (byte)92, (byte)25, (byte)215, (byte)133, (byte)198, (byte)73, (byte)205, (byte)35, (byte)153, (byte)182, (byte)56, (byte)222, (byte)254, (byte)251, (byte)222, (byte)168, (byte)201, (byte)235, (byte)18, (byte)10, (byte)136, (byte)251, (byte)203, (byte)47, (byte)243, (byte)58, (byte)205, (byte)83, (byte)222, (byte)251, (byte)87, (byte)111, (byte)230, (byte)74, (byte)240};
	public static byte[] ECDSARIPEMD160KEY = new byte[] {45, (byte)47, (byte)149, (byte)98, (byte)71, (byte)114, (byte)204, (byte)219, (byte)38, (byte)171, (byte)163, (byte)48, (byte)251, (byte)99, (byte)44, (byte)29, (byte)103, (byte)192, (byte)30, (byte)151, (byte)244, (byte)233, (byte)229, (byte)55, (byte)61, (byte)42, (byte)114, (byte)207, (byte)78, (byte)67, (byte)246, (byte)216, (byte)77, (byte)200, (byte)42, (byte)239, (byte)90, (byte)182, (byte)25, (byte)222, (byte)198, (byte)79, (byte)182, (byte)246, (byte)223, (byte)216, (byte)168, (byte)181, (byte)181, (byte)193, (byte)252, (byte)33, (byte)51, (byte)10, (byte)167, (byte)198, (byte)82, (byte)67, (byte)111, (byte)121, (byte)187, (byte)250, (byte)221, (byte)50};

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
