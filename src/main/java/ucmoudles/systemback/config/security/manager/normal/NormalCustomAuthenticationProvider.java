package ucmoudles.systemback.config.security.manager.normal;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;


@Configuration
public class NormalCustomAuthenticationProvider extends DaoAuthenticationProvider {

    private Logger logger = LoggerFactory.getLogger(NormalCustomAuthenticationProvider.class);

    public NormalCustomAuthenticationProvider(@Qualifier("customUserService") UserDetailsService userDetailsService){
        super();
        setUserDetailsService(userDetailsService);
    }

    @Override
    protected void additionalAuthenticationChecks(UserDetails userDetails, UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {

        //可拓展手机号-验证码登录
        logger.info("自定义登陆验证，用户名字为：" + authentication.getName());

        super.additionalAuthenticationChecks(userDetails, authentication);

    }

}
