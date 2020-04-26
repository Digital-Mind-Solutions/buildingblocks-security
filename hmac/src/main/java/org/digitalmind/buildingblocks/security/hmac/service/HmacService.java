package org.digitalmind.buildingblocks.security.hmac.service;

import org.digitalmind.buildingblocks.security.hmac.core.HmacAlgorithm;
import org.digitalmind.buildingblocks.security.hmac.exception.HmacFieldException;
import org.digitalmind.buildingblocks.security.hmac.exception.HmacSignExcception;
import org.digitalmind.buildingblocks.security.hmac.exception.HmacUrlExpiredException;

import java.util.Date;
import java.util.Map;
import java.util.Set;

public interface HmacService {

    public Map<String, Object> addTemporalMark(Map<String, Object> fields, int years, int months, int days, int hours, int minutes, int seconds);

    public Map<String, Object> addTemporalMark(Map<String, Object> fields, Date hmacDate, int years, int months, int days, int hours, int minutes, int seconds);

    public Map<String, Object> removeTemporalMark(Map<String, Object> fields);

    public String calculateHmac(String context, Map<String, Object> fields, Set<String> exceptedFields) throws HmacFieldException, HmacSignExcception;

    public boolean validateHmac(String context, String hmac, Map<String, Object> fields, Set<String> exceptedFields) throws HmacFieldException, HmacSignExcception;

    public String calculateUrl(String context, Map<String, Object> fields, Set<String> exceptedFields, String base, String fragment) throws HmacFieldException, HmacSignExcception;

    public boolean validateUrl(String context, String url, Set<String> exceptedFields, boolean throwExceptionOnExpiration) throws HmacSignExcception, HmacFieldException, HmacUrlExpiredException;

    public Map<String, Object> getUrlFields(String context, String url) throws HmacFieldException;

    public String getHmacEncoding(String context);

    public HmacAlgorithm getHmacAlgorithm(String context);

    public boolean isHmacEnabled(String context);

}
