package com.javatechie.entity;

import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static com.javatechie.entity.Permission.ADMIN_READ;
import static com.javatechie.entity.Permission.ADMIN_UPDATE;
import static com.javatechie.entity.Permission.ADMIN_CREATE;
import static com.javatechie.entity.Permission.ADMIN_DELETE;



public enum Role {

    USER(Collections.emptySet()),
    ADMIN(
            Set.of(
                    ADMIN_READ,
                    ADMIN_UPDATE,
                    ADMIN_DELETE,
                    ADMIN_CREATE
            )
    );
    private final Set<Permission> role;

    private Role(Set<Permission> role){
        this.role = role;
    }

    public Set<Permission> getPermissions(){
        return role;
    }

    public List<SimpleGrantedAuthority> getAuthorities() {
        var authorities = getPermissions()
                .stream()
                .map(permission -> new SimpleGrantedAuthority(permission.getPermission()))
                .collect(Collectors.toList());
        authorities.add(new SimpleGrantedAuthority("ROLE_" + this.name()));
        return authorities;
    }


}
