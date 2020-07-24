<?php

declare (strict_types=1);

namespace mark\auth;

use think\facade\Request;
use think\facade\Config;

use mark\http\Curl;
use mark\system\Os;

use mark\auth\sso\Sso;
use mark\auth\sso\driver\WeChat;
use mark\auth\sso\driver\AliPay;
use mark\auth\sso\driver\DingTalk;

/**
 * Class WeChat
 * 如果用户在微信客户端中访问第三方网页，公众号可以通过微信网页授权机制，来获取用户基本信息，进而实现业务逻辑。
 *
 * @package mark\auth\sso\driver
 */
class Client extends Sso {

    /**
     * 当前节点为主要节点，并且未跨域,直接跳转到登录界面，
     * Url应该统一为一个地址，具体显示应该由登录控制器根据参数输出
     *
     * @param string $scope
     *
     * @return array|bool|false|mixed|string|\think\response\Redirect
     * @author: Mark Zong
     */
    public function request($scope = '') {
        // 1、第一步：用户同意授权，获取code
        if (!Request::has("code", "get", true)) {
            return $this->getCode(
                Config::get('auth.appid'),
                Request::url(true),
                'code',
                $scope,
                md5(uniqid((string)time(), true))
            );
        }

        //2、第二步：通过code换取网页授权access_token
        $token = $this->getAccessToken(Config::get('auth.appid'), Config::get('auth.appsecret'), Request::get('code'));

        if ($token == false || empty($token['access_token']) || empty($token['openid'])) {
            return false;
        }

        if ($scope === 'auth_base') {
            return $token;
        }

        // TODO：这里已经获取到OpenId,可检查是否注册过，未注册则再申请UserInfo
        //4、第四步：拉取用户信息(需scope为 auth_userinfo)
        $userInfo = $this->getUserInfo($token['access_token'], $token['openid'], Config::get('lang.default_lang'));
        if (!empty($userInfo) && !empty($userInfo['openid'])) {
            return $userInfo;
        }

        return false;
    }

    /**
     * 第一步：用户同意授权，获取code
     * Authorize constructor.
     *
     * @explain      GET：{"code":"081PxY4C06i5ki2MNv5C0LCC4C0PxY4A","state":"5ae74940188ff277cb3ea5021d543ea0"}
     *
     * @param string $appid         公众号的唯一标识
     * @param string $redirect_uri  授权后重定向的回调链接地址， 请使用 urlEncode 对链接进行处理
     * @param string $response_type 返回类型，请填写code
     * @param string $scope         应用授权作用域，
     *                              auth_base （不弹出授权页面，直接跳转，只能获取用户openid），
     *                              auth_userinfo （弹出授权页面，可通过openid拿到昵称、性别、所在地。
     *                              auth_union (弹出授权页面，可通过OpenID获取到用户包括角色，群组在内的信息)
     *
     *                              并且， 即使在未关注的情况下，只要用户授权，也能获取其信息 ）
     * @param string $state         重定向后会带上state参数，开发者可以填写a-zA-Z0-9的参数值，最多128字节
     *
     * @return mixed
     * @link         https://developers.weixin.qq.com/doc/offiaccount/OA_Web_Apps/Wechat_webpage_authorization.html#0
     */
    public function getCode(string $appid, string $redirect_uri, string $response_type = 'code', string $scope = 'auth_base', string $state = '') {
        $url = Config::get('auth.host', 'https://auth.tianfu.ink') . '/auth.php/oauth2/authorize'
            . '?appid=' . $appid
            . '&redirect_uri=' . urlencode($redirect_uri)
            . '&response_type=' . $response_type
            . '&scope=' . $scope
            . '&state=' . $state ?? md5(uniqid((string)time(), true))
            . '&view=authorize'
            . '#auth_redirect';

        header('Location: ' . $url);

        return redirect($url);
    }

    /**
     * 第二步：通过code换取网页授权access_token
     *
     * @explain JSON：
     * {
     * "access_token":"ACCESS_TOKEN",
     * "expires_in":7200,
     * "refresh_token":"REFRESH_TOKEN",
     * "openid":"OPENID",
     * "scope":"SCOPE"
     * }
     * @link    https://developers.weixin.qq.com/doc/offiaccount/OA_Web_Apps/Wechat_webpage_authorization.html#2
     *
     * @param string $appid
     * @param string $secret
     * @param string $code 用于换取access_token的code，微信提供
     *
     * @return array|bool|false|string
     */
    public function getAccessToken(string $appid = '', string $secret = '', string $code = '') {
        $appid = $appid ?? Config::get('auth.appid');
        $secret = $secret ?? Config::get('auth.appsecret');
        $code = $code ?? Request::get('code');
        $url = Config::get('auth.host', 'https://auth.tianfu.ink')
            . '/auth.php/oauth2/access_token?appid=' . $appid . '&secret=' . $secret . '&code=' . $code . '&grant_type=authorization_code';

        $token = Curl::getInstance(true)->get($url)->toArray();

        if (!empty($token) && !empty($token['openid']) && !empty($token['access_token'])) {
            return $token;
        }

        if (empty($token) || isset($token['errcode'])) {
            return array();
        }

        return array();
    }

    /**
     * 3、第三步：刷新access_token（如果需要）
     *
     * @explain JSON：
     *{
     * "access_token":"ACCESS_TOKEN",
     * "expires_in":7200,
     * "refresh_token":"REFRESH_TOKEN",
     * "openid":"OPENID",
     * "scope":"SCOPE"
     * }
     *
     * @param string $appid         公众号的唯一标识
     * @param string $refresh_token 填写通过access_token获取到的refresh_token参数
     *
     * @return array|bool|false
     * @link    https://developers.weixin.qq.com/doc/offiaccount/OA_Web_Apps/Wechat_webpage_authorization.html#2
     */
    public function refreshToken(string $appid = '', string $refresh_token = '') {
        $appid = $appid ?? Config::get('auth.appid');
        $refresh_token = $refresh_token ?? Request::get('refresh_token');
        $url = Config::get('auth.host', 'https://auth.tianfu.ink')
            . '/auth.php/oauth2/refresh_token?appid=' . $appid . '&grant_type=refresh_token&refresh_token=' . $refresh_token;

        $token = Curl::getInstance()->get($url)->toArray();

        if (!empty($token) && !empty($token['access_token']) && !empty($token['refresh_token'])) {
            return $token;
        }

        return false;
    }

    /**
     * 4、第四步：拉取用户信息(需scope为 auth_userinfo)
     *
     * @param string $access_token 网页授权接口调用凭证,注意：此access_token与基础支持的access_token不同
     * @param string $openid       用户的唯一标识
     * @param string $lang         返回国家地区语言版本，zh_CN 简体，zh_TW 繁体，en 英语
     *
     * @return array|bool|false|string 微信用户信息数组
     * @link https://developers.weixin.qq.com/doc/offiaccount/OA_Web_Apps/Wechat_webpage_authorization.html#3
     */
    public function getUserInfo(string $access_token = '', string $openid = '', string $lang = 'zh_CN') {
        $access_token = $access_token ?? $this->getAccessToken()['access_token'];
        $openid = $openid ?? $this->getAccessToken()['openid'];
        $lang = $lang ?? Config::get('lang.default_lang');
        $url = Config::get('auth.host', 'https://auth.tianfu.ink')
            . '/auth.php/oauth2/userinfo?access_token=' . $access_token . '&openid=' . $openid . '&lang=' . $lang;
        $userinfo = Curl::getInstance()->get($url)->toArray();

        if (!empty($userinfo) && !empty($userinfo['openid']) && !empty($userinfo['nickname']) && !empty($userinfo['sex'])) {
            return $userinfo;
        }

        if (empty($userinfou) || isset($userinfo['errcode'])) {
            return array();
        }

        return $userinfo;
    }

    /**
     * 5、附：检验授权凭证（access_token）是否有效
     *{ "errcode":0,"errmsg":"ok"}
     *
     * @param string $access_token 网页授权接口调用凭证,注意：此access_token与基础支持的access_token不同
     * @param string $openid       用户的唯一标识
     *
     * @return bool
     * @link https://developers.weixin.qq.com/doc/offiaccount/OA_Web_Apps/Wechat_webpage_authorization.html#4
     */
    public function verifyToken(string $access_token, string $openid) {
        $token = $this->getAccessToken();

        $access_token = $access_token ?? $token['access_token'] ?? '';
        $openid = $openid ?? $token['openid'] ?? '';

        $url = Config::get('auth.host', 'https://auth.tianfu.ink') .
            '/auth.php/oauth2/verify_token?access_token=' . $access_token . '&openid=' . $openid;
        $result = Curl::getInstance()->get($url)->toArray();
        if (!empty($result) && !isset($result['errcode']) && $result['errcode'] == 0) {
            return true;
        }

        return false;
    }

    /**
     * 用户授权校验并请求
     *
     * @param string $appid
     * @param string $redirect_uri
     * @param string $response_type
     * @param string $scope
     * @param string $access_type
     * @param string $state
     *
     * @return \think\response\Redirect
     */
    public static function authentication(
        string $appid, string $redirect_uri, string $response_type = 'code', string $scope = 'auth_base', $access_type = 'offline', string $state = ''
    ) {
        $url = Config::get('auth.host', 'https://auth.tianfu.ink')
        . '/auth.php/authorize/choice'
        . '?appid=' . $appid
        . '&redirect_uri=' . urlencode($redirect_uri)
        . '&response_type=' . $response_type
        . '&scope=' . $scope
        . '&access_type=' . $access_type
        . '&state=' . !empty($state) ? $state : md5(uniqid((string)time(), true));

        header('Location:' . $url);

        return redirect($url);
    }

}