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
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;
import ucmoudles.systemback.config.security.filters.github.GithubAuthenticationFilter;
import ucmoudles.systemback.config.security.handlers.normal.NormalCustomAuthenticationFailHandler;
import ucmoudles.systemback.config.security.handlers.third.ThirdCommonAuthenticationFailHandler;
import ucmoudles.systemback.config.security.handlers.third.ThirdCommonAuthenticationSuccessHandler;
import ucmoudles.systemback.config.security.manager.normal.NormalCustomAuthenticationProvider;
import ucmoudles.systemback.config.security.handlers.normal.NormalCustomAuthenticationSuccessHandler;
import ucmoudles.systemback.config.security.filters.weibo.WeiBoAuthenticationFilter;
import ucmoudles.systemback.config.security.manager.third.ThirdAuthenticationManager;
import ucmoudles.systemback.constant.GitHubConstant;
import ucmoudles.systemback.constant.WeiBoConstant;

import javax.sql.DataSource;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private ThirdAuthenticationManager thirdAuthenticationManager;

    @Autowired
    private DataSource dataSource;

    @Value("${spring.security.remember-me.expire}")
    private Integer rememberMeExpire;



    @Autowired
    private NormalCustomAuthenticationSuccessHandler authenticationSuccessHandler;
    @Autowired
    private NormalCustomAuthenticationFailHandler authenticationFailHandler;
    @Autowired
    private ThirdCommonAuthenticationFailHandler thirdCommonAuthenticationFailHandler;
    @Autowired
    private ThirdCommonAuthenticationSuccessHandler thirdCommonAuthenticationSuccessHandler;

    @Override
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
        NormalCustomAuthenticationProvider provider = new NormalCustomAuthenticationProvider(customUserService());
        provider.setPasswordEncoder(passwordEncoder());
        auth.authenticationProvider(provider);
        auth.userDetailsService(customUserService()).passwordEncoder(passwordEncoder());

    }


    @Override
    protected void configure(HttpSecurity http) throws Exception {
            http.authorizeRequests()
                .antMatchers("/js/**","/css/**","/images/**","/system/**").permitAll().antMatchers("/login","/v5/**","/login/callback/**","/actuator/**").permitAll()
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
                 http.addFilterAt(weiBoAuthenticationProcessingFilter(), UsernamePasswordAuthenticationFilter.class);
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers("/css/**","/images/**","/js/**","system/**");
    }


    @Bean("customUserService")
    UserDetailsService customUserService() {
        return new NormalCustomUserService();
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

    @Bean
    public WeiBoAuthenticationFilter weiBoAuthenticationProcessingFilter() {
        WeiBoAuthenticationFilter filter = new WeiBoAuthenticationFilter(WeiBoConstant.callBackUri);
        filter.setAuthenticationManager(thirdAuthenticationManager);
        filter.setAuthenticationSuccessHandler(thirdCommonAuthenticationSuccessHandler);
        filter.setAuthenticationFailureHandler(thirdCommonAuthenticationFailHandler);
        return filter;
    }

    @Bean
    public GithubAuthenticationFilter githubAuthenticationFilter() {
        GithubAuthenticationFilter filter = new GithubAuthenticationFilter(GitHubConstant.callBackUri);
        filter.setAuthenticationManager(thirdAuthenticationManager);
        filter.setAuthenticationSuccessHandler(thirdCommonAuthenticationSuccessHandler);
        filter.setAuthenticationFailureHandler(thirdCommonAuthenticationFailHandler);
        return filter;
    }

}

