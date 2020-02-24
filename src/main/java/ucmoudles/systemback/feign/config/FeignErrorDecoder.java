package ucmoudles.systemback.feign.config;

import feign.Request;
import feign.Response;
import feign.Util;
import feign.codec.ErrorDecoder;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Configuration;
import ucmoudles.systemback.enums.ErrorCode;
import ucmoudles.systemback.exceptions.FeignFailException;

import java.io.IOException;

/**
 * @Auther: 9527
 * @Date:
 * @Description:
 */
@Configuration
@Slf4j
public class FeignErrorDecoder implements ErrorDecoder {
    @Override
    public Exception decode(String s, Response response) {
        String body = null;
        if (response.body() != null) {
            try {
                body = Util.toString(response.body().asReader());
            } catch (IOException e) {
                e.printStackTrace();
            }
            Request request = response.request();
            log.error("feign调用失败，request {},errorMsg {},code {}", request.toString(), body,response.status());

        }
        return new FeignFailException(ErrorCode.FEIGNFAIL.getCode(),ErrorCode.FEIGNFAIL.getMessage()+":"+body);
    }

}
