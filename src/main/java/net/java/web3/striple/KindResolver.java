package net.java.web3.striple;


public interface KindResolver {
	/**
	 * Note that resolution strategie could differ between application (different kindid, different kinds, different resolution when no id, different forbidden kind)
	 * @param kindId
	 * @param from, the striple with non initialized kind (or null) 
	 * @return the kind to use for the new Striple
	 */
	public StripleKind kindResolve (byte[] kindId, Striple from) throws StripleException;
	

}
