package org.digitalmind.buildingblocks.security.hmac.core;

import org.digitalmind.buildingblocks.security.hmac.exception.HmacFieldException;
import org.digitalmind.buildingblocks.security.hmac.exception.HmacSignExcception;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.regex.Pattern;

public class Hmac {
    public static SimpleDateFormat TIMESTAMP_FORMAT = new SimpleDateFormat("yyyyMMddHHmmss");
    private static final String HEXES = "0123456789abcdef";

    public static Map<String, Object> toFields(String values,
                                               final String encoding,
                                               final String valueDelimiter,
                                               final String itemDelimiter) throws HmacFieldException {
        Map<String, Object> fields = new HashMap<>();
        String itemDelimiterPattern = Pattern.quote(itemDelimiter);
        String valueDelimiterPattern = Pattern.quote(valueDelimiter);
        String[] items = values.split(itemDelimiterPattern);
        String key;
        String value;
        for (String item : items) {
            String[] parts = item.split(valueDelimiterPattern);
            try {
                key = URLDecoder.decode(parts[0], encoding);
            } catch (UnsupportedEncodingException exception) {
                throw new HmacFieldException("Unsupported Decoding Exception for field code: " + parts[0], exception);
            }
            try {
                value = URLDecoder.decode(parts[1], encoding);
            } catch (UnsupportedEncodingException exception) {
                throw new HmacFieldException("Unsupported Decoding Exception for field value: " + parts[1], exception);
            }
            fields.put(key, value);
        }
        return fields;
    }

    public static String getValueAsString(Object value) {
        String valueString = null;
        if (value != null) {
            if (value instanceof Date) {
                valueString = TIMESTAMP_FORMAT.format(value);
            } else {
                valueString = String.valueOf(value);
            }
        }
        return valueString;
    }

    public static Date getValueAsDate(Object value) throws HmacFieldException {
        Date valueDate = null;
        if (value != null) {
            if (value instanceof String) {
                try {
                    valueDate = TIMESTAMP_FORMAT.parse((String) value);
                } catch (ParseException exception) {
                    throw new HmacFieldException("Unable to parse " + value + " to date", exception);
                }
            } else {
                valueDate = (Date) value;
            }
        }
        return valueDate;
    }

    public static Long getValueAsLong(Object value) throws HmacFieldException {
        Long valueLong = null;
        if (value != null) {
            if (value instanceof String) {
                try {
                    valueLong = Long.valueOf((String) value);
                } catch (NumberFormatException exception) {
                    throw new HmacFieldException("Unable to convert " + value + " to long", exception);
                }
            } else {
                valueLong = (Long) value;
            }
        }
        return valueLong;
    }

    public static String toQueryString(Map<String, Object> fields,
                                       final String encoding,
                                       final String valueDelimiter,
                                       final String itemDelimiter,
                                       Set<String> exceptedFields) throws HmacFieldException {
        StringBuffer queryString = new StringBuffer();
        //Note that the fields must be sorted by field names when constructing the message to be signed
        Map<String, Object> sortedFields = new TreeMap<String, Object>(fields);
        for (Map.Entry<String, Object> entry : sortedFields.entrySet()) {
            if (exceptedFields == null || !exceptedFields.contains(entry.getKey())) {
                try {
                    queryString.append(URLEncoder.encode((String) entry.getKey(), encoding) + valueDelimiter);
                } catch (final UnsupportedEncodingException exception) {
                    throw new HmacFieldException("Unsupported Encoding Exception for field code: " + entry.getKey(), exception);
                }
                try {
                    queryString.append(URLEncoder.encode(getValueAsString(entry.getValue()), encoding) + itemDelimiter);
                } catch (final UnsupportedEncodingException exception) {
                    throw new HmacFieldException("Unsupported Encoding Exception  for field value: " + String.valueOf(entry.getValue()), exception);
                }
            }
        }
        if (queryString.length() > 0) {
            queryString.deleteCharAt(queryString.length() - 1);
        }
        return queryString.toString();
    }

    public static String toQueryString(Map<String, Object> fields,
                                       final String encoding,
                                       final String valueDelimiter,
                                       final String itemDelimiter) throws HmacFieldException {
        return toQueryString(fields, encoding, valueDelimiter, itemDelimiter, null);
    }

    /**
     * Converts the hash generated by the mac.doFinal method
     * to match the result of hmac generated via hash_hmac PHP function
     * this method must be used only if the 4th parameter of the hash_hmac was set to false
     * in case of calling hash_hmac with the 4th parameter set to true then
     * hmac value must be obtained by calling DatatypeConverter.printBase64Binary instead of the getHex method
     *
     * @param raw the hasg calculated using mac.doFinal method
     * @return returns a hmac using the same method as the equivalent php function
     * hash_hmac called with the 4th parameter set to false
     */
    private static String getHex(byte[] raw) {
        if (raw == null) {
            return null;
        }
        final StringBuilder hex = new StringBuilder(2 * raw.length);
        for (final byte b : raw) {
            hex.append(HEXES.charAt((b & 0xF0) >> 4)).append(HEXES.charAt((b & 0x0F)));
        }
        return hex.toString();
    }

    /**
     * Converts a string message into a HMAC hash based upon the provided
     * password, encoding charset and algorithm.
     *
     * @param secret    the password used for hashing
     * @param encoding  the charset encoding for hashing
     * @param algorithm the algorithm to be used during hashing
     * @param message   the string to be hashed with the specify algorithm
     * @return returns String with hashed message
     */

    public static String create(final String secret,
                                final String encoding,
                                final String algorithm,
                                final String message) throws HmacSignExcception {
        try {
            final SecretKeySpec signingKey = new SecretKeySpec(secret.getBytes(encoding), algorithm);
            final Mac mac = Mac.getInstance(algorithm);
            mac.init(signingKey);
            final byte[] expectedCodeBytes = mac.doFinal(message.getBytes(encoding));
            return DatatypeConverter.printBase64Binary(expectedCodeBytes);
        } catch (final NoSuchAlgorithmException exception) {
            throw new HmacSignExcception("Unsupported Message Authentication Code (MAC) algorithm: " + algorithm, exception);
        } catch (final InvalidKeyException exception) {
            throw new HmacSignExcception("Invalid code for Message Authentication Code (MAC)", exception);
        } catch (final IllegalArgumentException exception) {
            throw new HmacSignExcception("Invalid argument(s) in code for Message Authentication Code (MAC)", exception);
        } catch (IOException exception) {
            throw new HmacSignExcception("IOException for Message Authentication Code (MAC)", exception);
        }
    }

    /**
     * Validate a given hmac based on the provided
     * password, encoding charset and algorithm.
     *
     * @param hmac      the givem hmac to be validated
     * @param secret    the password used for hashing
     * @param encoding  the charset encoding for hashing
     * @param algorithm the algorithm to be used during hashing
     * @param message   the string to be hashed with the specify algorithm
     * @return returns true if hmac has been verified
     */
    public static boolean verify(final String hmac,
                                 final String secret,
                                 final String encoding,
                                 final String algorithm,
                                 final String message) throws HmacSignExcception {
        String hmacCalculated = create(secret, encoding, algorithm, message);
        return hmacCalculated.equals(hmac);
    }

}
