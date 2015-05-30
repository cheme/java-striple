package net.java.web3.striple;

public class StripleException extends Exception {
	/**
	 * 
	 */
	private static final long serialVersionUID = -1287638867219897777L;
	/**
	 * 
	 */
	public enum StripleExceptionType {
		UnexpectedStriple, DecodingError, KindImplementationNotFound, InvalidInput, Unimplemented, EmptyChannel,
	};
	
	StripleExceptionType type;
	String message;
	public StripleException(StripleExceptionType type, String message) {
		super();
		this.type = type;
		this.message = message;
	}
	

}
