package ucmoudles.systemback.config.security;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.ucs.moudlecommon.domain.SysUsers;
import com.ucs.moudlecommon.params.CommonParamsMoudle;
import com.ucs.moudlecommon.response.BaseResponse;
import lombok.SneakyThrows;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import ucmoudles.systemback.constant.SignatureConstant;
import ucmoudles.systemback.feign.service.Feign_Moudle_User;

import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class CustomUserService implements UserDetailsService {

    @Autowired
    private Feign_Moudle_User feign_moudle_user;

    private Logger logger = LoggerFactory.getLogger(CustomUserService.class);

    /**
     * 根据输入的内容判断手机登录还是密码登录
     * @param s
     * @return
     * @throws UsernameNotFoundException
     */
    @SneakyThrows
    @Override
    public UserDetails loadUserByUsername(String s) throws UsernameNotFoundException {
        CommonParamsMoudle moudle = new CommonParamsMoudle.Builder(SignatureConstant.commonSignaturePrefix_user,SignatureConstant.commonSignatureSuffix_user,SignatureConstant.commonSignatureKey_user).build();
        moudle.setExtra(s);
        BaseResponse resp = feign_moudle_user.findUserRoleInfo(moudle);
        if(!resp.isSuccess() || resp.getResult() == null){
            throw new UsernameNotFoundException("用户不存在");
        }
        Map result = Map.class.cast(resp.getResult());
        LinkedHashMap user = LinkedHashMap.class.cast(result.get("user"));
        List<String> auths = List.class.cast(result.get("auths"));
        return new UserDetails() {
            @Override
            public Collection<? extends GrantedAuthority> getAuthorities() {
                return AuthorityUtils.createAuthorityList(auths.toArray(new String[auths.size()]));
            }

            @Override
            public String getPassword() {
                return (String)user.get("memPassWord");
            }

            @Override
            public String getUsername() {
                return (String)user.get("memPhoneNumber");
            }

            @Override
            public boolean isAccountNonExpired() {
                return true;
            }

            @Override
            public boolean isAccountNonLocked() {
                return true;
            }

            @Override
            public boolean isCredentialsNonExpired() {
                return true;
            }

            @Override
            public boolean isEnabled() {
                return true;
            }
        };
    }


    public CustomUserService() {
        super();
    }
}
