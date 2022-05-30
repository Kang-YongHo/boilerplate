package com.demo.modules.common.type;

public enum Role {
    SUPER_ADMIN("ROLE_SUPER_ADMIN,ROLE_ADMIN"),
    ADMIN("ROLE_ADMIN"),
    USER("ROLE_USER");

    private final String role;

    Role(String role) {
        this.role = role;
    }

    public String getRole() {
        return this.role;
    }
}
