package net.java.web3.striple;

import java.security.PrivateKey;

public interface OwnedStriple extends Striple {
  public PrivateKey getPrivateKey();
  public byte[] encodePrivateKey();
}
