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
	public static byte[] PUBRIPEMKEY= new byte [] {73, (byte)90, (byte)215, (byte)66, (byte)44, (byte)149, (byte)161, (byte)92, (byte)107, (byte)78, (byte)148, (byte)106, (byte)215, (byte)87, (byte)129, (byte)116, (byte)62, (byte)244, (byte)33, (byte)236, (byte)84, (byte)165, (byte)176, (byte)116, (byte)86, (byte)238, (byte)126, (byte)181, (byte)94, (byte)238, (byte)82, (byte)100, (byte)110, (byte)190, (byte)109, (byte)151, (byte)252, (byte)33, (byte)98, (byte)195, (byte)27, (byte)70, (byte)152, (byte)140, (byte)215, (byte)64, (byte)117, (byte)233, (byte)157, (byte)106, (byte)181, (byte)231, (byte)226, (byte)0, (byte)34, (byte)102, (byte)120, (byte)171, (byte)235, (byte)157, (byte)121, (byte)114, (byte)207, (byte)98};
	public static byte[] PUBSHA512KEY = new byte[] {47, (byte)72, (byte)77, (byte)220, (byte)196, (byte)219, (byte)0, (byte)90, (byte)244, (byte)218, (byte)2, (byte)142, (byte)183, (byte)206, (byte)183, (byte)196, (byte)110, (byte)227, (byte)15, (byte)151, (byte)239, (byte)9, (byte)184, (byte)102, (byte)197, (byte)90, (byte)77, (byte)34, (byte)70, (byte)188, (byte)103, (byte)215, (byte)184, (byte)203, (byte)19, (byte)34, (byte)166, (byte)179, (byte)219, (byte)105, (byte)144, (byte)15, (byte)198, (byte)9, (byte)29, (byte)197, (byte)121, (byte)127, (byte)21, (byte)13, (byte)192, (byte)134, (byte)145, (byte)222, (byte)219, (byte)31, (byte)215, (byte)40, (byte)143, (byte)114, (byte)239, (byte)39, (byte)200, (byte)16};
	public static byte[] PUBSHA256KEY = new byte[] {59, (byte)240, (byte)107, (byte)33, (byte)144, (byte)162, (byte)215, (byte)253, (byte)232, (byte)129, (byte)27, (byte)205, (byte)90, (byte)155, (byte)111, (byte)24, (byte)6, (byte)28, (byte)214, (byte)191, (byte)45, (byte)246, (byte)234, (byte)193, (byte)62, (byte)27, (byte)122, (byte)24, (byte)206, (byte)2, (byte)68, (byte)75, (byte)105, (byte)6, (byte)128, (byte)160, (byte)66, (byte)106, (byte)169, (byte)42, (byte)58, (byte)248, (byte)51, (byte)193, (byte)200, (byte)207, (byte)162, (byte)112, (byte)106, (byte)167, (byte)56, (byte)144, (byte)111, (byte)62, (byte)198, (byte)100, (byte)105, (byte)139, (byte)11, (byte)241, (byte)187, (byte)162, (byte)18, (byte)78};
	public static byte[] RSA2048SHA512KEY = new byte[] {127, (byte)167, (byte)178, (byte)248, (byte)64, (byte)157, (byte)233, (byte)139, (byte)30, (byte)84, (byte)124, (byte)56, (byte)254, (byte)241, (byte)210, (byte)136, (byte)250, (byte)200, (byte)19, (byte)181, (byte)165, (byte)0, (byte)97, (byte)125, (byte)193, (byte)101, (byte)42, (byte)146, (byte)20, (byte)72, (byte)12, (byte)3, (byte)248, (byte)130, (byte)9, (byte)25, (byte)20, (byte)89, (byte)236, (byte)225, (byte)143, (byte)194, (byte)182, (byte)198, (byte)24, (byte)107, (byte)94, (byte)69, (byte)140, (byte)17, (byte)62, (byte)186, (byte)219, (byte)73, (byte)203, (byte)255, (byte)208, (byte)106, (byte)249, (byte)117, (byte)195, (byte)120, (byte)146, (byte)10};
	public static byte[] ECDSARIPEMD160KEY = new byte[] {(byte) 251, (byte)114, (byte)205, (byte)46, (byte)70, (byte)161, (byte)171, (byte)177, (byte)56, (byte)170, (byte)59, (byte)8, (byte)204, (byte)229, (byte)188, (byte)224, (byte)139, (byte)16, (byte)21, (byte)57, (byte)14, (byte)247, (byte)89, (byte)116, (byte)30, (byte)97, (byte)158, (byte)236, (byte)42, (byte)57, (byte)183, (byte)61, (byte)232, (byte)205, (byte)150, (byte)170, (byte)179, (byte)75, (byte)20, (byte)165, (byte)39, (byte)140, (byte)83, (byte)167, (byte)178, (byte)188, (byte)171, (byte)118, (byte)233, (byte)65, (byte)107, (byte)89, (byte)221, (byte)13, (byte)68, (byte)27, (byte)44, (byte)186, (byte)93, (byte)82, (byte)233, (byte)175, (byte)236, (byte)25};


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
