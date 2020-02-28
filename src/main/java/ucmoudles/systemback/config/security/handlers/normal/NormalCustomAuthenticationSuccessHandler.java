package ucmoudles.systemback.config.security.handlers.normal;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@Component
public class NormalCustomAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    public static final String RETURN_TYPE = "json"; // 登录成功时，用来判断是返回json数据还是跳转html页面

    private Logger logger = LoggerFactory.getLogger(NormalCustomAuthenticationSuccessHandler.class);

    @Autowired
    private ObjectMapper objectMapper;

    private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {

        logger.info("登录成功");
        logger.info("username=>" + request.getParameter("username"));
        if(RETURN_TYPE.equals("html")) {
            redirectStrategy.sendRedirect(request, response, "/login/success");
        } else {
            Map<String, Object> map = new HashMap<>();
            map.put("code",200);
            map.put("msg","登录成功");
            map.put("data",authentication);
            response.setContentType("application/json;charset=UTF-8");
            response.getWriter().write(objectMapper.writeValueAsString(map));
        }
    }
}
