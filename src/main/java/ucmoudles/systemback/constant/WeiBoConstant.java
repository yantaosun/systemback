package ucmoudles.systemback.constant;/** * @author 9527 * @ClassName WeiBoConstant * @Date 2020/1/23 * @Description TODO * @Version 1.0 */public class WeiBoConstant {    //微博应用appId    public static final  String appKey = "3271903632";    //微博应用app secret    public static final String appSecret = "9826518dc28e058a0e4b43318289dffb";    //登录回调地址    public static final String callBack = "http://127.0.0.1:8884/login/callback/weibo";    //授权认证获取code    public static final String authorize = "https://api.weibo.com/oauth2/authorize";    //授权认证获取token    public static final String accesstoken = "https://api.weibo.com/oauth2/access_token";    //授权认证获取userinfo    public static final String userinfo = "https://api.weibo.com/2/users/show.json";}