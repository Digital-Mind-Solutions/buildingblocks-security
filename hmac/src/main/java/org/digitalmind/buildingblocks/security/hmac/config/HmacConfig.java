package org.digitalmind.buildingblocks.security.hmac.config;

import lombok.Getter;
import lombok.Setter;
import org.digitalmind.buildingblocks.security.hmac.dto.HmacUrlProperties;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.ArrayList;
import java.util.List;

import static org.digitalmind.buildingblocks.security.hmac.config.HmacModuleConfig.ENABLED;
import static org.digitalmind.buildingblocks.security.hmac.config.HmacModuleConfig.PREFIX;

@Configuration
@ConditionalOnProperty(name = ENABLED, havingValue = "true")
@ConfigurationProperties(prefix = PREFIX)
@EnableConfigurationProperties
@Getter
@Setter
public class HmacConfig {
    private boolean enabled;
    private String defaultName;
    private List<HmacUrlProperties> config = new ArrayList<HmacUrlProperties>();
}
