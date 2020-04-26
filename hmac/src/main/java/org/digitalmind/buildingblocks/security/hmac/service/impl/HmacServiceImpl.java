package org.digitalmind.buildingblocks.security.hmac.service.impl;

import lombok.extern.slf4j.Slf4j;
import org.digitalmind.buildingblocks.security.hmac.config.HmacConfig;
import org.digitalmind.buildingblocks.security.hmac.core.HmacAlgorithm;
import org.digitalmind.buildingblocks.security.hmac.core.HmacUrl;
import org.digitalmind.buildingblocks.security.hmac.dto.HmacUrlProperties;
import org.digitalmind.buildingblocks.security.hmac.exception.HmacFieldException;
import org.digitalmind.buildingblocks.security.hmac.exception.HmacSignExcception;
import org.digitalmind.buildingblocks.security.hmac.exception.HmacUrlExpiredException;
import org.digitalmind.buildingblocks.security.hmac.service.HmacService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;

import java.util.Calendar;
import java.util.Date;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static org.digitalmind.buildingblocks.security.hmac.config.HmacModuleConfig.ENABLED;
import static org.digitalmind.buildingblocks.security.hmac.core.HmacUrl.FIELD_HMAC_TIMESTAMP;
import static org.digitalmind.buildingblocks.security.hmac.core.HmacUrl.FIELD_HMAC_TTL;

@Slf4j
@Service
@ConditionalOnProperty(name = ENABLED, havingValue = "true")
public class HmacServiceImpl implements HmacService {
    private final HmacConfig config;
    private final Map<String, HmacUrlProperties> urlPropertiesMap;

    @Autowired
    public HmacServiceImpl(HmacConfig config) {
        this.config = config;
        urlPropertiesMap = this.config.getConfig().stream()
                .filter(t -> t.isEnabled())
                .collect(Collectors.toMap(t -> t.getName(), t -> t));
        log.info("HmacServiceImpl service initialized");
    }

    public HmacUrlProperties getHmacUrlProperties(String context) {
        if (this.urlPropertiesMap != null && this.urlPropertiesMap.containsKey(context)) {
            return this.urlPropertiesMap.get(context);
        }
        return this.urlPropertiesMap.get(this.config.getDefaultName());
    }

    public String getHmacEncoding(String context) {
        return this.getHmacUrlProperties(context).getEncoding();
    }

    public HmacAlgorithm getHmacAlgorithm(String context) {
        return this.getHmacUrlProperties(context).getAlgorithm();
    }

    public boolean isHmacEnabled(String context) {
        return this.getHmacUrlProperties(context).isEnabled();
    }

    protected HmacUrl.HmacUrlBuilder getBuilder(String context) {
        HmacUrlProperties hmacUrlProperties = this.getHmacUrlProperties(context);
        HmacUrl.HmacUrlBuilder builder = HmacUrl.builder();
        builder.algorithm(hmacUrlProperties.getAlgorithm());
        builder.encoding(hmacUrlProperties.getEncoding());
        builder.secret(hmacUrlProperties.getSecret());
        return builder;
    }


    public Map<String, Object> addTemporalMark(Map<String, Object> fields, int years, int months, int days, int hours, int minutes, int seconds) {
        return addTemporalMark(fields, new Date(), years, months, days, hours, minutes, seconds);
    }

    public Map<String, Object> addTemporalMark(Map<String, Object> fields, Date hmacDate, int years, int months, int days, int hours, int minutes, int seconds) {
        Calendar calendar = Calendar.getInstance();
        long hmacDateMillis = hmacDate.getTime();

        calendar.setTime(hmacDate);
        if (years > 0) {
            calendar.add(Calendar.YEAR, years);
        }
        if (months > 0) {
            calendar.add(Calendar.MONTH, months);
        }
        if (days > 0) {
            calendar.add(Calendar.HOUR, days * 24);
        }
        if (hours > 0) {
            calendar.add(Calendar.HOUR, hours);
        }
        if (minutes > 0) {
            calendar.add(Calendar.MINUTE, minutes);
        }
        if (seconds > 0) {
            calendar.add(Calendar.SECOND, seconds);
        }
        long hmacDateExpireMillis = calendar.getTimeInMillis();
        long offset = (hmacDateExpireMillis - hmacDateMillis) / 1000;

        fields.put(FIELD_HMAC_TIMESTAMP, hmacDate);
        fields.put(FIELD_HMAC_TTL, offset);
        return fields;
    }

    public Map<String, Object> removeTemporalMark(Map<String, Object> fields) {
        fields.remove(FIELD_HMAC_TIMESTAMP);
        fields.remove(FIELD_HMAC_TTL);
        return fields;
    }

    public String calculateHmac(String context, Map<String, Object> fields, Set<String> exceptedFields) throws HmacFieldException, HmacSignExcception {
        HmacUrl.HmacUrlBuilder builder = getBuilder(context);
        builder.fields(fields);
        builder.exceptedFields(exceptedFields);
        return builder.build().calculateHmac();
    }

    public boolean validateHmac(String context, String hmac, Map<String, Object> fields, Set<String> exceptedFields) throws HmacFieldException, HmacSignExcception {
        String hmacCalculated = calculateHmac(context, fields, exceptedFields);
        return hmacCalculated.equals(hmac);
    }

    public String calculateUrl(String context, Map<String, Object> fields, Set<String> exceptedFields, String base, String fragment) throws HmacFieldException, HmacSignExcception {
        HmacUrl.HmacUrlBuilder builder = getBuilder(context);
        builder.fields(fields);
        builder.exceptedFields(exceptedFields);
        builder.base(base);
        builder.fragment(fragment);
        return builder.build().calculateUrl();
    }

    public boolean validateUrl(String context, String url, Set<String> exceptedFields, boolean throwExceptionOnExpiration) throws HmacSignExcception, HmacFieldException, HmacUrlExpiredException {
        HmacUrl.HmacUrlBuilder builder = getBuilder(context);
        builder.exceptedFields(exceptedFields);
        return builder.build().validateUrl(url, throwExceptionOnExpiration);
    }

    public Map<String, Object> getUrlFields(String context, String url) throws HmacFieldException {
        HmacUrl.HmacUrlBuilder builder = getBuilder(context);
        return builder.build().getUrlFields(url);
    }
}
