package net.yxy.chukonu.spring.security.config;

import org.apache.commons.codec.digest.DigestUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private UserService userService;


    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable()
                .exceptionHandling()
                .authenticationEntryPoint(new UnauthorizedEntryPoint()) // entrypoint for anonymous 
                .accessDeniedHandler(new CustomAccessDeineHandler()) // handler for logged in users but no enough permission
                .and()
                .headers().frameOptions().disable() // resolve 'X-Frame-Options' to 'deny' issue
                .and()
                .authorizeRequests()
                .antMatchers("/login.html").permitAll()
                .anyRequest()
                .authenticated()
                .and()
                .httpBasic()
                .and()
                .formLogin()
                .loginPage("/login.html")
                .loginProcessingUrl("/login")
                .successHandler(new SimpleUrlAuthenticationSuccessHandler())
                .failureHandler(new SimpleUrlAuthenticationFailureHandler())
                .and()
                //the “never” option will ensure that Spring Security itself will not create any session; 
                //however, if the application creates one, then Spring Security will make use of it.
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.NEVER)
                                    .maximumSessions(1).maxSessionsPreventsLogin(true)
                                    .expiredUrl("/sessionExpired.html").and()
                                    .invalidSessionUrl("/invalidSession.html")
                                    // Session Fixation Protection with Spring Security
                                    // when “none” is set, the original session will not be invalidated
                                    // when “newSession” is set, a clean session will be created without any of the attributes from the old session being copied over
                                    .sessionFixation().newSession()
                .and().logout();

    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(authenticationProvider());
    }

    @Bean
    public DaoAuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        // config UserDetail Implementation class to handle login verification
        authProvider.setUserDetailsService(userService); 
        authProvider.setPasswordEncoder(encoder());
        return authProvider;
    }
    
    @Bean
    public PasswordEncoder encoder() {
        return new PasswordEncoder() {

            @Override
            public String encode(CharSequence rawPassword) {
                return DigestUtils.md5Hex(rawPassword.toString().getBytes());
            }

            @Override
            public boolean matches(CharSequence rawPassword, String encodedPassword) {
                return encodedPassword.equals(DigestUtils.md5Hex(rawPassword.toString().getBytes()));
            }
        };
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers("/js/**");
//        web.ignoring().antMatchers("/v2/api-docs", 
//                                   "/swagger-resources", 
//                                   "/swagger-resources/**", 
//                                   "/configuration/ui", 
//                                   "/configuration/security", 
//                                   "/swagger-ui.html", 
//                                   "/webjars/**");
    }

}
