package com.telusko.spring_sec_demo.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Autowired
    private UserDetailsService userDetailsService;

    @Bean
    public AuthenticationProvider authProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(userDetailsService);
        provider.setPasswordEncoder(new BCryptPasswordEncoder(12));
        return provider;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        // Without Lambda -----------------------------------
        http.csrf(customizer -> customizer.disable())
                .authorizeHttpRequests(request -> request.anyRequest().authenticated())
                .httpBasic(Customizer.withDefaults())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        // With Lambda---------------------------------------

        // // disable csrf
        // http.csrf(customizer -> customizer.disable());

        // // for every request authenicate it
        // http.authorizeHttpRequests(request -> request.anyRequest().authenticated());

        // // Enable the form
        // // http.formLogin(Customizer.withDefaults());

        // // Enables HTTP Basic authentication
        // http.httpBasic(Customizer.withDefaults());

        // // Make the Session stateless: the application will not create or use HTTP
        // // sessions to store security information. Instead, every request must be
        // // independently authenticated.
        // http.sessionManagement(session ->
        // session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        return http.build();
    }

    // @Bean
    // public UserDetailsService userDetailsService() {

    // UserDetails user = User
    // .withDefaultPasswordEncoder()
    // .username("david")
    // .password("1234")
    // .roles("USER")
    // .build();

    // UserDetails admin = User
    // .withDefaultPasswordEncoder()
    // .username("admin")
    // .password("admin@789")
    // .roles("ADMIN")
    // .build();

    // return new InMemoryUserDetailsManager(user, admin);
    // }
}
