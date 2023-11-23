package com.fwa.ec.learn.base_project.service;

import com.fwa.ec.learn.base_project.entity.SecurityUser;
import com.fwa.ec.learn.base_project.repository.SystemUserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class SystemUserDetailsService implements UserDetailsService {
    private final SystemUserRepository userRepository;

    public SystemUserDetailsService(SystemUserRepository userRepository) {
        this.userRepository = userRepository;
    }


    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        return userRepository.findAllByUsername(username).map(SecurityUser::new).orElseThrow(()-> new UsernameNotFoundException("No user found with name "+ username));

    }
}
