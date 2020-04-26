package org.digitalmind.buildingblocks.security.hmac.exception;

public class HmacUrlExpiredException extends HmacException {
    public HmacUrlExpiredException() {
    }

    public HmacUrlExpiredException(String message) {
        super(message);
    }

    public HmacUrlExpiredException(String message, Throwable cause) {
        super(message, cause);
    }

    public HmacUrlExpiredException(Throwable cause) {
        super(cause);
    }

    public HmacUrlExpiredException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
