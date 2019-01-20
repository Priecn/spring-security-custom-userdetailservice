package learn.security;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@SpringBootApplication
public class CustomUserdetailserviceApplication {

    @Bean
    PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }

    @Bean
    CustomUserDetailsService customUserDetailsService() {

        Collection<UserDetails> userDetails = Arrays.asList(
                new CustomUserDetails("jlong", "password", true, new String[] {"USER"}),
                new CustomUserDetails("rwinch", "password", true, "USER", "ADMIN")
        );

        return new CustomUserDetailsService(userDetails);
    }

    public static void main(String[] args) {
        SpringApplication.run(CustomUserdetailserviceApplication.class, args);
    }

}

@Configuration
@EnableWebSecurity
class CustomSecurityConfiguration extends WebSecurityConfigurerAdapter {


    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.formLogin();
        http.authorizeRequests().anyRequest().authenticated();
    }

}

@RestController
class GreetingRestController {

    @GetMapping("/greeting")
    public String greet(Principal principal) {
        return "hello "+ principal.getName();
    }
}


class CustomUserDetailsService implements UserDetailsService {

    private final Map<String, UserDetails> users = new ConcurrentHashMap<>();

    public CustomUserDetailsService(Collection<UserDetails> seedUsers) {
        seedUsers.forEach( user -> this.users.put(user.getUsername(), user));
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        if(this.users.containsKey(username))
            return this.users.get(username);
        throw new UsernameNotFoundException("couldn't find user "+ username);
    }
}


class CustomUserDetails implements UserDetails {

    private final String username, password;
    private final boolean active;

    private final Set<GrantedAuthority> authorities = new HashSet<>();
    public CustomUserDetails(String username, String password, boolean active, String ... authorities) {
        this.username = username;
        this.password = password;
        this.active = active;
        this.authorities.addAll(Stream.of(authorities)
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toSet()));
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return this.authorities;
    }

    @Override
    public String getPassword() {
        return this.password;
    }

    @Override
    public String getUsername() {
        return this.username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return this.active;
    }

    @Override
    public boolean isAccountNonLocked() {
        return this.active;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return this.active;
    }

    @Override
    public boolean isEnabled() {
        return this.active;
    }
}