package ucmoudles.systemback.config.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import ucmoudles.systemback.config.redis.RedisBusiness;


@Configuration
public class CustomAuthenticationProvider extends DaoAuthenticationProvider {

    private Logger logger = LoggerFactory.getLogger(CustomAuthenticationProvider.class);

    private RedisBusiness redisClient;

    public CustomAuthenticationProvider(@Qualifier("customUserService") UserDetailsService userDetailsService,  RedisBusiness redisClient){
        super();
        setUserDetailsService(userDetailsService);
        setRedisClient(redisClient);
    }

    public void setRedisClient(RedisBusiness redisClient) { this.redisClient = redisClient; }

    @Override
    protected void additionalAuthenticationChecks(UserDetails userDetails, UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {

        //可拓展手机号-验证码登录
        logger.info("自定义登陆验证，用户名字为：" + authentication.getName());

        super.additionalAuthenticationChecks(userDetails, authentication);

    }

}
