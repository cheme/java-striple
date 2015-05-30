package net.java.web3.striple.storage;

import net.java.web3.striple.StripleMethods;



public class RemoveKey implements StorageCypher {

	public int getIdVal() {
		return 0;
	}

	public byte[] getCypherHeader() {
		return StripleMethods.xtendsize(this.getIdVal(),HEADER_ID_VAL_LENGTH);
	}

	public byte[] encrypt(byte[] dec) {
		return new byte[]{};
	}

	public byte[] decrypt(byte[] enc) {
		return new byte[]{};
	}

}
