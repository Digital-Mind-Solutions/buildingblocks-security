package org.digitalmind.buildingblocks.security.hmac.exception;

public class HmacSignExcception extends HmacException{
    public HmacSignExcception() {
    }

    public HmacSignExcception(String message) {
        super(message);
    }

    public HmacSignExcception(String message, Throwable cause) {
        super(message, cause);
    }

    public HmacSignExcception(Throwable cause) {
        super(cause);
    }

    public HmacSignExcception(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
