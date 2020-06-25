<?php

namespace mark\src\sso\driver;

use mark\src\sso\Sso;
use think\facade\Log;
use think\facade\Request;
use think\facade\Config;

class WeChat extends Sso {

    /**
     * 用户同意授权，获取code
     * Authorize constructor.
     *
     * public $index_url = "https://account.nyhbqc.com/account.php/authorize/auth";  //微信回调地址，要跟公众平台的配置域名相同
     * 参数        是否必须    说明
     *
     * appid                公众号的唯一标识
     * redirect_uri                授权后重定向的回调链接地址， 请使用 urlEncode 对链接进行处理
     * response_type                返回类型，请填写code
     * scope                        应用授权作用域，snsapi_base （不弹出授权页面，直接跳转，只能获取用户openid），
     * snsapi_userinfo （弹出授权页面，可通过openid拿到昵称、性别、所在地。并且， 即使在未关注的情况下，只要用户授权，也能获取其信息 ）
     * state                        重定向后会带上state参数，开发者可以填写a-zA-Z0-9的参数值，最多128字节
     * #wechat_redirect            无论直接打开还是做页面302重定向时候，必须带此参数
     *
     * @return bool|mixed
     */
    public function request() {
        // Log::info("如果SESSION中没有openid，说明用户刚刚登陆，就执行getCode、getOpenId、getUserInfo获取他的信息::" . json_encode($_GET));
        if (!Request::has("code", "get", true)) {
            return $this->getCode(Request::url(true));
        }

        //获取网页授权access_token和用户openid
        $token = $this->getAccessToken(Request::get('code'));
        if (!$token) {
            Log::error('WeChat::Request(getAccessToken Token Null)');

            return $this->getCode(Request::url(true));
        }

        Log::info('WeChat::Request(Token True)' . json_encode($token));
        // TODO：这里已经获取到OpenId,可检查是否注册过，未注册则再申请UserInfo
        $userInfo = $this->getUserInfo($token['access_token'], $token['openid']);//获取微信用户信息
        if (!empty($userInfo) && !empty($userInfo['openid'])) {
            Log::info('WeChat::Request(UserInfo True)' . json_encode($userInfo) . ' getType::' . gettype($userInfo));

            return $userInfo;
        }

        Log::error('WeChat::Request(getUserInfo is null) ' . json_encode($userInfo));

        return false;
    }

    /**
     * 第一步：用户同意授权，获取code
     *
     * @explain      获取code,用于获取openid和access_token
     * @remark       code只能使用一次，当获取到之后code失效,再次获取需要重新进入
     * 不会弹出授权页面，适用于关注公众号后自定义菜单跳转等，如果不关注，那么只能获取openid
     *
     * @explain      GET：{"code":"081PxY4C06i5ki2MNv5C0LCC4C0PxY4A","state":"5ae74940188ff277cb3ea5021d543ea0"}
     *
     * @param        $callback
     *
     * @return bool|mixed
     */
    public function getCode($callback) {
        $url = 'https://open.weixin.qq.com/connect/oauth2/authorize?'
            . 'appid=' . Config::get('auth.stores.wechat.appid')
            . '&redirect_uri=' . urlencode($callback)
            . '&response_type=' . Config::get('auth.stores.wechat.response_type', 'code')
            // . "&scope=" . Config::get("auth.stores.wechat.scope", "snsapi_base")
            . '&scope=' . ($this->auth->scope === 'snsapi_userinfo' ? 'snsapi_userinfo' : 'snsapi_base')
            . '&state=' . Config::get('auth.stores.wechat.state', md5(uniqid((string)time(), true)))
            . '#wechat_redirect';

        Log::info("WeChat::getCode::Url($url)");
        header('Location: ' . $url);

        return false;
        // return redirect($url);
    }

    /**
     * 第二步：通过code换取网页授权access_token
     *
     * @param string 用于换取access_token的code，微信提供
     *
     * @return bool
     *
     * @explain JSON：
     * {
     * "access_token":"ACCESS_TOKEN",
     * "expires_in":7200,
     * "refresh_token":"REFRESH_TOKEN",
     * "openid":"OPENID",
     * "scope":"SCOPE"
     * }
     */
    public function getAccessToken($code) {
        $url = 'https://api.weixin.qq.com/sns/oauth2/access_token' .
            '?appid=' . Config::get('auth.stores.wechat.appid') .
            '&secret=' . Config::get('auth.stores.wechat.secret') .
            '&code=' . $code . '&grant_type=authorization_code';

        $json = $this->curl->get($url)->execute();
        Log::info("WeChat::getAccessToken($json)");
        $array = json_decode($json, true);

        if (!empty($array) && isset($array['errcode'])) {
            Log::info('WeChat::getAccessToken::(False 错误返回)' . json_encode($array));

            return false;
        }

        return $array;
    }

    /**
     * 第三步：刷新access_token（如果需要）
     */
    public function refreshToken() {
    }

    /**
     * 附：检验授权凭证（access_token）是否有效
     */
    public function verifyToken() {
    }
    /**
     *
     **
     * 通过code获取用户openid以及用户的微信号信息
     * 获取到用户的openid之后可以判断用户是否有数据，可以直接跳过获取access_token,也可以继续获取access_token
     * access_token每日获取次数是有限制的，access_token有时间限制，可以存储到数据库7200s. 7200s后access_token失效
     **/

    /**
     * 第四步：拉取用户信息(需scope为 snsapi_userinfo)
     * 4、使用access_token获取用户信息
     *
     * @param $token
     * @param $openid
     *
     * @return bool|mixed
     */
    public function getUserInfo($token, $openid) {
        // $url = "https://api.weixin.qq.com/sns/userinfo?access_token=" . $token . "&openid=" . $openid . "&lang=zh_CN";
        $url = 'https://api.weixin.qq.com/sns/userinfo?access_token=' . $token . '&openid=' . $openid . '&lang=' . Config::get(
                'lang.default_lang'
            );
        $json = $this->curl->get($url)->execute();
        Log::info("WeChat::getUserInfo($url)");
        Log::info("WeChat::getUserInfo($json)");
        $array = json_decode($json, true);

        if (isset($array['errcode'])) {
            Log::info('WeChat::getUserInfo(False 错误返回)' . json_encode($array));

            return false;
        }

        if (empty($array) || empty($array['openid']) || !isset($array['openid'])) {
            Log::error('WeChat::getUserInfo(False OpenID 无效)' . json_encode($array));

            return false;
        }

        return $array;
    }

}