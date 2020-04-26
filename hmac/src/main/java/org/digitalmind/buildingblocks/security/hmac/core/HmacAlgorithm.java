package org.digitalmind.buildingblocks.security.hmac.core;

public enum HmacAlgorithm {
    HmacMD5("HmacMD5"),
    HmacSHA1("HmacSHA1"),
    HmacSHA256("HmacSHA256");

    private String algorithm;

    private HmacAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }

    public String getAlgorithm() {
        return this.algorithm;
    }
}
