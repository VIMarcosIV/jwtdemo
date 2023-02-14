package org.iesch.ad.jwtdemo.configuration;

import org.iesch.ad.jwtdemo.filters.JwtRequestFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
public class WebSecurityConfig {

    @Autowired
    JwtRequestFilter jwtRequestFilter;

    //Hacer que la cadena de filtrado se comporte como YO quiera
    @Bean
    public SecurityFilterChain filterChain (HttpSecurity http) throws Exception{

        http.csrf().disable()
                //se hace publico t0d0 lo de /public
                .authorizeRequests().antMatchers("/public/**").permitAll()
                //solo se puede acceder a lo de admin si tienes el rol de ADMIN
                .antMatchers("/admin/**").hasRole("ADMIN").anyRequest().authenticated()
                //que se cree el jwt y se lo mande al cliente, nada de guardarlo
                .and().sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        http.addFilterBefore(jwtRequestFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();

    }

}
