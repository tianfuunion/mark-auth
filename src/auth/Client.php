<?php

declare (strict_types=1);

namespace mark\auth;

use think\facade\Request;
use mark\http\Curl;
use think\facade\Config;
use mark\auth\entity\UserInfo;

class Client {

    /** @var Authorize */
    protected $auth;

    /**@var Curl */
    protected $curl;

    public function __construct(Authorize $auth) {
        $this->auth = $auth;
        $this->curl = Curl::getInstance();
    }

    /**
     * 当前节点为主要节点，直接跳转到登录界面，
     * Url应该统一为一个地址，具体显示应该由登录控制器根据参数输出
     *
     * 当前节点为应用节点，并且未跨域
     *
     * @return \think\response\Redirect
     */
    public function request() {
        return redirect(Config::get('auth.host') . '/auth.php/login/login?backurl=' . urlencode(Request::url(true)));
    }

    /**
     * 获取code后，请求以下链接获取access_token：
     *  https://api.weixin.qq.com/sns/oauth2/access_token?appid=APPID&secret=SECRET&code=CODE&grant_type=authorization_code
     */
    public function access_token() {

    }

    /**
     * 获取第二步的refresh_token后，请求以下链接获取access_token：
     * https://api.weixin.qq.com/sns/oauth2/refresh_token?appid=APPID&grant_type=refresh_token&refresh_token=REFRESH_TOKEN
     */
    public function refresh_token() {
    }

    /**
     * http：GET（请使用https协议）
     * https://api.weixin.qq.com/sns/userinfo?access_token=ACCESS_TOKEN&openid=OPENID&lang=zh_CN
     */
    public function userinfo() {
    }

    private static $user;
    private static $email;

    /**
     * @return \mark\auth\entity\UserInfo
     */
    public static function user() {
        if (self::$user == null) {
            self::$user = new UserInfo();
        }

        return self::$user;
    }

    /**
     * @return \mark\auth\entity\UserInfo
     */
    public static function email() {
        if (self::$user == null) {
            self::$user = new UserInfo();
        }

        if (!empty(self::$user)) {
            return self::$user;
        }

        return new UserInfo();

    }

}