package org.iesch.ad.jwtdemo.services;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.Map;

public class UsersDetailsService implements UserDetailsService {
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Map<String, String> users = Map.of(
                "Diego", "USER",
                "Admin", "ADMIN"
        );
        var role = users.get(username);

        if (role != null){
            User.UserBuilder userBuilder = User.withUsername(username);
            String pass = "{noop}" + "1234";
            userBuilder.password(pass).roles(role);
            return userBuilder.build();
        } else {
            throw new UsernameNotFoundException(username);
        }

    }
}
