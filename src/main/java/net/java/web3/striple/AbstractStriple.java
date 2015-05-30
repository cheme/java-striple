package net.java.web3.striple;

import java.io.IOException;

/**
 * abstract striple for extends when possible (no need to use static methods).
 * 
 * @author cheme
 *
 */
public abstract class AbstractStriple implements Striple {
  
  public byte[] getToSig() throws IOException {
	  return StripleMethods.getToSig(this);
  };
  
  public boolean checkId(Striple from) {
	  return StripleMethods.checkId(from, this);
  };

  public boolean checkSig(Striple from) {
	  return StripleMethods.checkSig(from, this);
  };

  public boolean check(Striple from) {
	  return StripleMethods.check(from, this);
  };

  public byte[] stripleSer() throws IOException {
	  return StripleMethods.stripleSer(this);
  };

  static public Striple stripleDSer(byte[] bytes, Striple checkfrom, KindResolver k) throws StripleException {
	  return StripleMethods.stripleDSer(bytes,checkfrom,k);
  };

  public byte[] encode_key() {
		return StripleMethods.encode_key(this);
  }

  public boolean is_public() {
		return StripleMethods.is_public(this);
  };
}
