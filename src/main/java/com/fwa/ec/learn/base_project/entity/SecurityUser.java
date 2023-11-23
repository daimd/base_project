package com.fwa.ec.learn.base_project.entity;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Arrays;
import java.util.Collection;

@RequiredArgsConstructor
public class SecurityUser  implements UserDetails {

    private final SystemUser systemUser;


//    public SecurityUser(SystemUser systemUser) {
//        this.systemUser = systemUser;
//    }

    @Override
    public String getUsername() {
        return systemUser.getUsername();
    }

    @Override
    public String getPassword() {
        return systemUser.getPassword();
    }
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return Arrays.stream(systemUser.getRole().split(",")).map(SimpleGrantedAuthority::new).toList();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
