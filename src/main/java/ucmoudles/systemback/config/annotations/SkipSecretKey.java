package ucmoudles.systemback.config.annotations;import java.lang.annotation.*;@Target({ElementType.METHOD, ElementType.TYPE})@Retention(RetentionPolicy.RUNTIME)@Documentedpublic @interface SkipSecretKey {}