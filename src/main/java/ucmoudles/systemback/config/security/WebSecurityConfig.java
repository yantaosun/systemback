package ucmoudles.systemback.config.security;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;
import ucmoudles.systemback.config.redis.RedisBusiness;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.sql.DataSource;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    public class CustomRememberMeService implements RememberMeServices{

        @Override
        public Authentication autoLogin(HttpServletRequest request, HttpServletResponse response) {
            return null;
        }

        @Override
        public void loginFail(HttpServletRequest request, HttpServletResponse response) {

        }

        @Override
        public void loginSuccess(HttpServletRequest request, HttpServletResponse response, Authentication successfulAuthentication) {

        }
    }

    @Autowired
    private DataSource dataSource;

    @Value("${spring.security.remember-me.expire}")
    private Integer rememberMeExpire;

    @Bean("customUserService")
    UserDetailsService customUserService() {
        return new CustomUserService();
    }

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public PersistentTokenRepository persistentTokenRepository(){
        JdbcTokenRepositoryImpl jdbcTokenRepository = new JdbcTokenRepositoryImpl();
        jdbcTokenRepository.setDataSource(dataSource);
        //jdbcTokenRepository.setCreateTableOnStartup(true);
        return jdbcTokenRepository;
    }

    @Autowired
    public RedisBusiness redisClient;
    @Autowired
    private CustomAuthenticationSuccessHandler authenticationSuccessHandler;
    @Autowired
    private CustomAuthenticationFailHandler authenticationFailHandler;


    @Override
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
        CustomAuthenticationProvider provider = new CustomAuthenticationProvider(customUserService(),redisClient);
        provider.setPasswordEncoder(passwordEncoder());
        auth.authenticationProvider(provider);
        auth.userDetailsService(customUserService()).passwordEncoder(passwordEncoder());

    }


    @Override
    protected void configure(HttpSecurity http) throws Exception {
            http.authorizeRequests()
                .antMatchers("/js/**","/css/**","/images/**","/system/**").permitAll().antMatchers("/login","/v5/**","/login/callback/**").permitAll()
                .anyRequest().authenticated()
                .and().csrf().and()
                .headers().frameOptions().disable()
                .and()
                .formLogin()
                      .loginPage("/login")
                      .loginProcessingUrl("/login")
                      .successHandler(authenticationSuccessHandler)
                      .failureHandler(authenticationFailHandler)
                      .and().logout().logoutUrl("/loginout").permitAll()
                      .and().rememberMe().tokenRepository(persistentTokenRepository()).tokenValiditySeconds(rememberMeExpire).userDetailsService(customUserService());

    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers("/css/**","/images/**","/js/**","system/**");
    }

    public static void main(String[] args) {
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
        System.out.println(encoder.encode("admin"));;
    }
}

