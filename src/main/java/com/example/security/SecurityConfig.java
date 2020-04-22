package com.example.security;

import com.example.security.Handler.LoginFailureHandler;
import com.example.security.Handler.TaskImplementingLogoutHandler;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.sql.DataSource;

@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Autowired
    private DataSource dataSource;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers("/adminOnly").hasAuthority("ROLE_ADMIN")
                .antMatchers("/**").permitAll() // 넓은 범위의 URL을 아래로 배치
                .anyRequest().authenticated()
                .and()
                .csrf().disable()
                .formLogin().loginPage("/login").failureUrl("/login?error").permitAll()
//                .failureHandler(CustomfailureHandler())
                .defaultSuccessUrl("/report")
                .and()
                .logout().logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
                .addLogoutHandler(new TaskImplementingLogoutHandler()).permitAll().logoutSuccessUrl("/login?logout");
                // 로그아웃 기본 url은 /logout
    }
    /*
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("admin")
                .password(passwordEncoder().encode("1234")).roles("ADMIN")
                .and()
                .withUser("guest")
                .password(passwordEncoder().encode("1234")).roles("GUEST");
    }
    */
    /**/
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.jdbcAuthentication()
                .dataSource(dataSource)
                .rolePrefix("ROLE_")
                .usersByUsernameQuery("select username, password, enabled from users where username = ?")
                .authoritiesByUsernameQuery("select username, role from users where username = ?");
    }

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationFailureHandler CustomfailureHandler() { return new LoginFailureHandler(); }
}
