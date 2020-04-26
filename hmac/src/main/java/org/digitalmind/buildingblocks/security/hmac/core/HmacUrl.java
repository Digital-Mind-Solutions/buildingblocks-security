package org.digitalmind.buildingblocks.security.hmac.core;

import lombok.*;
import lombok.extern.slf4j.Slf4j;
import org.digitalmind.buildingblocks.security.hmac.exception.HmacFieldException;
import org.digitalmind.buildingblocks.security.hmac.exception.HmacSignExcception;
import org.digitalmind.buildingblocks.security.hmac.exception.HmacUrlExpiredException;

import java.util.*;


@Slf4j
@Getter
@Builder(buildMethodName = "buildInternal", builderClassName = "HmacUrlBuilder")
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor(access = AccessLevel.PROTECTED)
public class HmacUrl {
    public static String FIELD_HMAC = "hmac".toLowerCase();
    public static String FIELD_HMAC_TIMESTAMP = "hmac-ts".toLowerCase();
    public static String FIELD_HMAC_TTL = "hmac-ttl".toLowerCase(); //in seconds
    public static String ENCODING_UTF8 = "UTF-8";

    public static String URL_VALUE_DELIMITER = "=";
    public static String URL_ITEM_DELIMITER = "&";


    public static long FIELD_HMAC_TTL_1DAY = 24 * 60 * 60;

    @Singular
    private Map<String, Object> fields;
    @Singular
    private Set<String> exceptedFields;
    private HmacAlgorithm algorithm;
    private String secret;

    private String encoding;
    private String base;
    private String fragment;
    private Date timestamp;
    private Long timeToLive;
    private String hmac;

    public static class HmacUrlBuilder {
        public HmacUrl build() {
            HmacUrl hmacUrl = this.buildInternal();
            hmacUrl.init();
            return hmacUrl;
        }
    }

    protected void init() {
        if (this.fields == null) {
            this.fields = new HashMap<>();
        } else {
            Map<String, Object> f = new HashMap<>();
            f.putAll(this.fields);
            this.fields = f;
        }
        if (this.exceptedFields == null) {
            this.exceptedFields = new HashSet();
            clearExceptedFields();
        } else {
            Set<String> ef = new HashSet<>();
            ef.addAll(this.exceptedFields);
            this.exceptedFields = ef;
        }
        this.exceptedFields.add(FIELD_HMAC);
        if (this.base != null) {
            if (this.base.endsWith("/")) {
                this.base = this.base.substring(0, this.base.length() - 1);
            }
        }
        if (this.fragment != null) {
            if (this.fragment.startsWith("#")) {
                this.fragment = this.fragment.substring(1);
            }
        }
        if (this.algorithm == null) {
            this.algorithm = HmacAlgorithm.HmacSHA256;
        }
        if (this.encoding == null) {
            this.encoding = ENCODING_UTF8;
        }
        if (this.timeToLive != null) {
            if (this.timestamp == null) {
                this.timestamp = new Date();
            }
        }
    }

    protected void setTimestamp(Date timestamp) throws HmacFieldException {
        this.timestamp = timestamp;
        setField(FIELD_HMAC_TIMESTAMP, this.timestamp);
    }

    protected void setTimeToLive(Long timeToLive) throws HmacFieldException {
        this.timeToLive = timeToLive;
        setField(FIELD_HMAC_TTL, this.timeToLive);
    }

    protected void setHmac(String hmac) throws HmacFieldException {
        this.hmac = hmac;
        setField(FIELD_HMAC, this.hmac);
    }

    protected void clearFields() {
        this.fields.clear();
    }

    protected void setField(String name, Object value) throws HmacFieldException {
        Object valueConverted;
        if (name.equalsIgnoreCase(FIELD_HMAC)) {
            valueConverted = String.valueOf(value);
            this.hmac = (String) valueConverted;
        } else if (name.equalsIgnoreCase(FIELD_HMAC_TIMESTAMP)) {
            valueConverted = Hmac.getValueAsDate(value);
            this.timestamp = (Date) valueConverted;
        } else if (name.equalsIgnoreCase(FIELD_HMAC_TTL)) {
            valueConverted = Hmac.getValueAsLong(value);
            this.timeToLive = (Long) valueConverted;
        } else {
            valueConverted = value;
        }

        if (valueConverted == null) {
            this.fields.remove(name);
        } else {
            this.fields.put(name, valueConverted);
        }
    }

    public Object getField(String name) {

        if (name.equalsIgnoreCase(FIELD_HMAC)) {
            return this.hmac;
        } else if (name.equalsIgnoreCase(FIELD_HMAC_TIMESTAMP)) {
            return this.timestamp;
        } else if (name.equalsIgnoreCase(FIELD_HMAC_TTL)) {
            return this.timeToLive;
        } else {
            return this.fields.get(name);
        }
    }

    public boolean hasField(String name) {
        return this.fields.containsKey(name);
    }

    protected void setExceptedField(String name) {
        this.exceptedFields.add(name);
    }

    public Object isExceptedField(String name) {
        return this.exceptedFields.contains(name);
    }

    protected void clearExceptedFields() {
        this.exceptedFields.clear();
    }

    @Synchronized
    public String calculateHmac() throws HmacFieldException, HmacSignExcception {
        String hmacParams = calculateParams(false);
        String hmacValue = Hmac.create(this.secret, this.encoding, this.algorithm.getAlgorithm(), hmacParams);
        return hmacValue;
    }

    protected String calculateParams(boolean includeExceptedFields) throws HmacFieldException {
        setExceptedField(FIELD_HMAC);
        Set<String> ef = (includeExceptedFields)
                ? new HashSet() {{
            add(FIELD_HMAC);
        }}
                : this.getExceptedFields();
        if (this.encoding == null) {
            this.encoding = ENCODING_UTF8;
        }
        String hmacParams = Hmac.toQueryString(this.fields, this.encoding, URL_VALUE_DELIMITER, URL_ITEM_DELIMITER, ef);
        return hmacParams;
    }

    @Synchronized
    public String calculateUrl() throws HmacFieldException, HmacSignExcception {
        String url = null;
        String hmac = calculateHmac();
        setField(FIELD_HMAC, hmac);
        String hmacParams = Hmac.toQueryString(this.fields, this.encoding, URL_VALUE_DELIMITER, URL_ITEM_DELIMITER, null);
        url = this.base + "/?" + hmacParams + ((this.fragment != null && !this.fragment.isEmpty()) ? "#" + this.fragment : "");
        return url;
    }

    public Map<String, Object> getUrlFields(String url) throws HmacFieldException {
        Map<String, Object> fields = null;
        int intPosStart = url.indexOf("/?");
        int intPosEnd = url.lastIndexOf("#");
        if (intPosEnd == -1) {
            intPosEnd = url.length();
        }

        String hmacParams = url.substring(intPosStart + 2, intPosEnd - 1);
        fields = Hmac.toFields(hmacParams, this.encoding, URL_VALUE_DELIMITER, URL_ITEM_DELIMITER);
        return fields;
    }

    @Synchronized
    public boolean validateUrl(String url, boolean throwExceptionOnExpiration) throws HmacFieldException, HmacSignExcception, HmacUrlExpiredException {
        if (url.indexOf("?") < 0) {
            throw new HmacFieldException("The url provided does not have query parameters");
        }
        this.base = url.substring(0, url.indexOf("?") - 1);
        int fragmentIndex = url.lastIndexOf("#");
        this.fragment = (fragmentIndex > 0) ? url.substring(fragmentIndex + 1) : null;
        String queryParameters = url.substring(this.base.length() + 2, url.length() - ((this.fragment == null) ? 0 : this.fragment.length() + 1));

        Map<String, Object> queryParamMap = Hmac.toFields(queryParameters, this.encoding, URL_VALUE_DELIMITER, URL_ITEM_DELIMITER);
        if (queryParamMap.containsKey(FIELD_HMAC_TIMESTAMP)) {
            queryParamMap.put(FIELD_HMAC_TIMESTAMP, Hmac.getValueAsDate(queryParamMap.get(FIELD_HMAC_TIMESTAMP)));
        }
        if (queryParamMap.containsKey(FIELD_HMAC_TTL)) {
            queryParamMap.put(FIELD_HMAC_TTL, Hmac.getValueAsLong(queryParamMap.get(FIELD_HMAC_TTL)));
        }

        clearFields();
        for (Map.Entry<String, Object> entry : queryParamMap.entrySet()) {
            setField(entry.getKey(), entry.getValue());
        }

        String queryHmac = getHmac();
        String calcHmac = calculateHmac();
        if (queryHmac.equals(calcHmac)) {
            //test expiration
            if (getTimeToLive() != null) {
                if (getTimestamp() == null) {
                    if (throwExceptionOnExpiration) {
                        throw new HmacUrlExpiredException("The url has ttl and no hmac date");
                    } else {
                        return false;
                    }
                }
                long hmacDateMillis = this.getTimestamp().getTime();
                long hmacExpireMillis = hmacDateMillis + (getTimeToLive() * 1000);
                boolean expired = (System.currentTimeMillis() >= hmacExpireMillis);
                if (expired) {
                    if (throwExceptionOnExpiration) {
                        throw new HmacUrlExpiredException("The url has expired");
                    } else {
                        return false;
                    }
                } else {
                    return true;
                }
            } else {
                return true;
            }
        }
        return false;
    }

}
