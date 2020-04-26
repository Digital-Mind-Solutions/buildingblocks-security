package org.digitalmind.buildingblocks.security.hmac.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.digitalmind.buildingblocks.security.hmac.core.HmacAlgorithm;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class HmacUrlProperties {
    protected String name;
    protected boolean enabled;
    protected String secret;
    protected HmacAlgorithm algorithm;
    protected String encoding;
}
