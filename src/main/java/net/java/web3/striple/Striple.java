package net.java.web3.striple;

import java.io.IOException;
import java.security.PublicKey;

/**
 * Striple interface.
 * @author cheme
 *
 */
public interface Striple {
	
  public byte[] getContEnc();
  /**
   * getter for striple id
   * @return
   */
  public byte[] getId();
  /**
   * getter for striple from
   * @return
   */
  public byte[] getFrom();
  public byte[] getAbout();
  public byte[] getContent();
  public byte[][] getContentIds();
  public PublicKey getKey();
  public byte[] getSig();
  public StripleKind getKind();
  
  
  public boolean checkId(Striple from);
  public boolean checkSig(Striple from);
  public boolean check(Striple from);
  public byte[] stripleSer() throws IOException;
  public byte[] encode_key();
  public boolean is_public();
}
