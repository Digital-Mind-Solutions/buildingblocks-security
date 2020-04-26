package org.digitalmind.buildingblocks.security.hmac.exception;

public abstract class HmacException extends Exception {
    public HmacException() {
    }

    public HmacException(String message) {
        super(message);
    }

    public HmacException(String message, Throwable cause) {
        super(message, cause);
    }

    public HmacException(Throwable cause) {
        super(cause);
    }

    public HmacException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
