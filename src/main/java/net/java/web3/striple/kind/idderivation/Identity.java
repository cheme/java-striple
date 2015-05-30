package net.java.web3.striple.kind.idderivation;

import java.util.Arrays;

import net.java.web3.striple.IDDerivation;
/**
 * For signature of the right size we simply not derive.
 * @author cheme
 *
 */
public class Identity implements IDDerivation {

	public byte[] deriveID(byte[] sig) {
		return sig;
	}

	public boolean checkIDDerivation(byte[] sig, byte[] id) {
		return Arrays.equals(sig,id);
	}

}
