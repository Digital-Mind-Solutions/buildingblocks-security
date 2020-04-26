package org.digitalmind.buildingblocks.security.hmac.exception;

public class HmacFieldException extends HmacException{
    public HmacFieldException() {
    }

    public HmacFieldException(String message) {
        super(message);
    }

    public HmacFieldException(String message, Throwable cause) {
        super(message, cause);
    }

    public HmacFieldException(Throwable cause) {
        super(cause);
    }

    public HmacFieldException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
