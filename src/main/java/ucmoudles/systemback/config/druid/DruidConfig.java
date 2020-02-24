package ucmoudles.systemback.config.druid;import com.alibaba.druid.support.http.StatViewServlet;import com.alibaba.druid.support.http.WebStatFilter;import org.springframework.beans.factory.annotation.Value;import org.springframework.boot.web.servlet.FilterRegistrationBean;import org.springframework.boot.web.servlet.ServletRegistrationBean;import org.springframework.context.annotation.Bean;import org.springframework.context.annotation.Configuration;import java.util.Arrays;import java.util.HashMap;import java.util.Map;/** * @author 9527 * @ClassName DruidConfig * @Date 2020/1/19 * @Description TODO * @Version 1.0 */@Configurationpublic class DruidConfig {    @Value("${spring.datasource.druid.username}")    private String username;    @Value("${spring.datasource.druid.password}")    private String password;    @Value("${spring.datasource.druid.whitelist}")    private String whitelist;    /**     * 配置druid监控     * 配置一个管理后台的servlet     * 访问地址：http://localhost:8080/druid/     * @return     */    @Bean    public ServletRegistrationBean statViewServlet() {        ServletRegistrationBean bean = new ServletRegistrationBean(new StatViewServlet(), "/druid/*");        Map<String, String> initParameters = new HashMap<String, String>();        initParameters.put("loginUsername", username);//属性见：com.alibaba.druid.support.http.ResourceServlet        initParameters.put("loginPassword", password);        initParameters.put("allow", whitelist);//默认允许所有        initParameters.put("deny", "");        bean.setInitParameters(initParameters);        return bean;    }    /**     * 配置一个web监控的filter     * @return     */    @Bean    public FilterRegistrationBean webStatFilter() {        FilterRegistrationBean filterBean = new FilterRegistrationBean();        filterBean.setFilter(new WebStatFilter());        filterBean.setUrlPatterns(Arrays.asList("/*"));        Map<String, String> initParameters = new HashMap<String, String>();        initParameters.put("exclusions", "*.js,*.css,/druid/*");//属性见：com.alibaba.druid.support.http.WebStatFilter        filterBean.setInitParameters(initParameters);        return filterBean;    }}