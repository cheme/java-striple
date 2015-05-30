package net.java.web3.striple;

public interface IDDerivation {
  public byte[] deriveID(byte[] sig);
  public boolean checkIDDerivation(byte[] sig, byte[] id);
}
