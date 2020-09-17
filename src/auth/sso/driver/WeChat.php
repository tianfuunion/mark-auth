<?php

declare (strict_types=1);

namespace mark\auth\sso\driver;

use mark\auth\sso\Sso;
use mark\http\Curl;

use think\facade\Config;
use think\facade\Request;
use think\response\Redirect;

/**
 * Class WeChat
 * 如果用户在微信客户端中访问第三方网页，公众号可以通过微信网页授权机制，来获取用户基本信息，进而实现业务逻辑。
 *
 * @package mark\auth\sso\driver
 */
class WeChat extends Sso {

    /**
     * 用户同意授权，获取code
     * Authorize constructor.
     *
     * @param string $scope
     *
     * @return array|bool|false|mixed|string|\think\response\Redirect
     */
    public function request($scope = 'snsapi_base') {
        // 1、第一步：用户同意授权，获取code
        if (!Request::has("code", "get", true)) {
            $result = $this->getCode(
                Config::get('auth.stores.wechat.appid'),
                Request::url(true),
                Config::get('auth.stores.wechat.response_type', 'code'),
                $scope == 'snsapi_userinfo' ? 'snsapi_userinfo' : 'snsapi_base',
                Config::get('auth.stores.wechat.state', md5(uniqid((string)time(), true)))
            );
            if ($result instanceof Redirect) {
                return $result;
            }

            return false;
        }

        //2、第二步：通过code换取网页授权access_token
        $token = $this->getAccessToken(Config::get('auth.stores.wechat.appid'), Config::get('auth.stores.wechat.secret'), Request::get('code'));
        if ($token == false || empty($token['access_token']) || empty($token['openid'])) {

            return false;
        }

        if ($scope === 'snsapi_base') {
            // return $token;
        }

        //4、第四步：拉取用户信息(需scope为 snsapi_userinfo)
        $userInfo = $this->getUserInfo($token['access_token'], $token['openid'], Config::get('lang.default_lang'));
        if (!empty($userInfo) && !empty($userInfo['openid'])) {
            return $userInfo;
        }

        return false;
    }

    /**
     * @param string $appid
     * @param string $secret
     * @param string $redirect_uri
     * @param string $response_type
     * @param string $scope
     * @param string $state
     * @param string $lang
     *
     * @return array|bool|false|mixed|string|\think\response\Redirect
     */
    public function authorize(string $appid, string $secret, string $redirect_uri, $response_type = 'code', $scope = 'snsapi_base', $state = '', $lang = 'zh-cn') {

        // 1、第一步：用户同意授权，获取code
        if (!Request::has("code", "get", true)) {
            $result = $this->getCode(
                $appid,
                $redirect_uri,
                $response_type ?: 'code',
                $scope == 'snsapi_userinfo' ? 'snsapi_userinfo' : 'snsapi_base',
                $state ?: md5(uniqid((string)time(), true))
            );
            if ($result instanceof Redirect) {
                return $result;
            }

            return false;
        }

        //2、第二步：通过code换取网页授权access_token
        $token = $this->getAccessToken($appid, $secret, Request::get('code'));
        if ($token == false || empty($token['access_token']) || empty($token['openid'])) {

            return false;
        }

        if ($scope === 'snsapi_base') {
            // return $token;
        }

        //4、第四步：拉取用户信息(需scope为 snsapi_userinfo)
        $userInfo = $this->getUserInfo($token['access_token'], $token['openid'], $lang);
        if (!empty($userInfo) && !empty($userInfo['openid'])) {
            return $userInfo;
        }

        return false;
    }

    /**
     * 第一步：用户同意授权，获取code
     *
     * @explain      GET：{"code":"081PxY4C06i5ki2MNv5C0LCC4C0PxY4A","state":"5ae74940188ff277cb3ea5021d543ea0"}
     *
     * @param string $appid         公众号的唯一标识
     * @param string $redirect_uri  授权后重定向的回调链接地址， 请使用 urlEncode 对链接进行处理
     * @param string $response_type 返回类型，请填写code
     * @param string $scope         应用授权作用域，snsapi_base （不弹出授权页面，直接跳转，只能获取用户openid），snsapi_userinfo （弹出授权页面，可通过openid拿到昵称、性别、所在地。
     *                              并且， 即使在未关注的情况下，只要用户授权，也能获取其信息 ）
     * @param string $state         重定向后会带上state参数，开发者可以填写a-zA-Z0-9的参数值，最多128字节
     *
     * @return mixed
     * @link         https://developers.weixin.qq.com/doc/offiaccount/OA_Web_Apps/Wechat_webpage_authorization.html#0
     */
    public function getCode(string $appid, string $redirect_uri, string $response_type = 'code', string $scope = 'snsapi_base', string $state = '') {
        $url = 'https://open.weixin.qq.com/connect/oauth2/authorize?'
            . 'appid=' . $appid
            . '&redirect_uri=' . urlencode($redirect_uri)
            . '&response_type=' . $response_type
            . '&scope=' . $scope
            . '&state=' . $state
            . '#wechat_redirect';

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
     * @return array|bool|false|mixed|string
     * @throws \Psr\SimpleCache\InvalidArgumentException
     */
    public function getAccessToken(string $appid, string $secret, string $code) {
        $cacheKey = 'wechat:access_token:appid:' . $appid . ':secret:' . $secret;

        if ($this->getCache()->has($cacheKey)) {
            $token = $this->getCache()->get($cacheKey);
            if (!empty($token) && !empty($token['openid']) && !empty($token['access_token'])) {
                return $token;
            }
        }

        $url = 'https://api.weixin.qq.com/sns/oauth2/access_token?appid=' . $appid . '&secret=' . $secret . '&code=' . $code . '&grant_type=authorization_code';
        $token = Curl::getInstance(true)
                     ->get($url)
                     ->toArray();

        if (!empty($token) && !empty($token['openid']) && !empty($token['access_token'])) {
            $this->getCache()->set($cacheKey, $token, 7000);

            return $token;
        }

        if (!empty($token['errcode'])) {
            return false;
        }

        return $token;
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
    public function refreshToken(string $appid, string $refresh_token) {
        $url = 'https://api.weixin.qq.com/sns/oauth2/refresh_token?appid=' . $appid . '&grant_type=refresh_token&refresh_token=' . $refresh_token;

        $token = Curl::getInstance(true)
                     ->get($url)
                     ->toArray();

        if (!empty($token) && !empty($token['access_token']) && !empty($token['refresh_token'])) {
            return $token;
        }

        return false;
    }

    /**
     * 4、第四步：拉取用户信息(需scope为 snsapi_userinfo)
     *
     * @param string $access_token 网页授权接口调用凭证,注意：此access_token与基础支持的access_token不同
     * @param string $openid       用户的唯一标识
     * @param string $lang         返回国家地区语言版本，zh_CN 简体，zh_TW 繁体，en 英语
     *
     * @return array|bool|false|string
     * @link https://developers.weixin.qq.com/doc/offiaccount/OA_Web_Apps/Wechat_webpage_authorization.html#3
     */
    public function getUserInfo(string $access_token, string $openid, string $lang = 'zh_CN') {
        $url = 'https://api.weixin.qq.com/sns/userinfo?access_token=' . $access_token . '&openid=' . $openid . '&lang=' . $lang;
        $userinfo = Curl::getInstance(true)
                        ->get($url)
                        ->toArray();

        if (!empty($userinfo) && !empty($userinfo['openid']) && !empty($userinfo['nickname']) && !empty($userinfo['sex'])) {
            return $userinfo;
        }

        if (!empty($userinfo['errcode'])) {
            return false;
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
        $url = 'https://api.weixin.qq.com/sns/auth?access_token=' . $access_token . '&openid=' . $openid;
        $result = Curl::getInstance(true)
                      ->get($url)
                      ->toArray();
        if (!empty($result['errcode']) && $result['errcode'] == 0) {
            return true;
        }

        return false;
    }

}