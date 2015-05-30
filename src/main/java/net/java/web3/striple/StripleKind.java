package net.java.web3.striple;


public interface StripleKind {
    public byte[] getKindId();
    public IDDerivation getIDDerivation();
    public SignatureScheme getSignatureScheme();
}
