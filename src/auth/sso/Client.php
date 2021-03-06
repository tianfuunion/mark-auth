<?php

declare (strict_types=1);

namespace mark\auth\sso;

use think\facade\Request;
use think\facade\Config;
use think\facade\Log;

use mark\http\Curl;
use mark\auth\Authorize;

/**
 * 如果用户在微信客户端中访问第三方网页，公众号可以通过微信网页授权机制，来获取用户基本信息，进而实现业务逻辑。
 *
 * Class Client
 *
 * @package mark\auth\sso
 */
class Client extends Sso {

    /**
     * 当前节点为主要节点，并且未跨域,直接跳转到登录界面，
     * Url应该统一为一个地址，具体显示应该由登录控制器根据参数输出
     *
     * @param string $scope
     *
     * @return array|bool|mixed|\think\response\Redirect
     * @throws \Psr\SimpleCache\InvalidArgumentException
     * @deprecated
     *
     * @author: Mark Zong
     */
    public function request($scope = 'auth_base') {
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
            Log::error('Client::request(NOT access_token Or openid)' . json_encode($token, JSON_UNESCAPED_UNICODE));

            return false;
        }

        if ($scope === 'auth_base') {
            return $token;
        }

        // TODO：这里已经获取到OpenId,可检查是否注册过，未注册则再申请UserInfo
        // TODO：获取OpenID后，检查是否注册过。可选择绑定帐号或者注册新帐号
        //4、第四步：拉取用户信息(需scope为 auth_userinfo)
        $userInfo = $this->getUserInfo($token['access_token'], $token['openid'], Config::get('lang.default_lang'));
        if (!empty($userInfo) && !empty($userInfo['openid'])) {
            return $userInfo;
        }
        Log::error('Client::request(false)' . json_encode($token, JSON_UNESCAPED_UNICODE));

        return false;
    }

    /**
     * 获取用户授权信息
     *
     * @param        $appid
     * @param string $secret
     * @param string $redirect_uri
     * @param string $response_type
     * @param string $scope
     * @param string $state
     * @param string $lang
     *
     * @return array|bool|mixed|\think\response\Redirect
     * @throws \Psr\SimpleCache\InvalidArgumentException
     */
    public function authorize($appid, string $secret, string $redirect_uri, $response_type = 'code', $scope = 'auth_base', $state = '', $lang = 'zh-cn') {
        // 1、第一步：用户同意授权，获取code
        if (!Request::has("code", "get", true)) {
            return $this->getCode(
                $appid,
                $redirect_uri,
                $response_type ?: 'code',
                $scope ?: 'auth_base',
                $state ?: md5(uniqid((string)time(), true))
            );
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
     * @return \think\response\Redirect
     * @link         https://developers.weixin.qq.com/doc/offiaccount/OA_Web_Apps/Wechat_webpage_authorization.html#0
     */
    public function getCode($appid, string $redirect_uri, $response_type = 'code', $scope = 'auth_base', $state = '') {
        $url = Config::get('auth.host', Authorize::$host)
            . '/auth.php/oauth2/authorize'
            . '?appid=' . $appid
            . '&redirect_uri=' . urlencode($redirect_uri)
            . '&response_type=' . $response_type
            . '&scope=' . $scope
            . '&access_type=offline'
            . '&view=authorize'
            . '&state=' . ($state ?? md5(uniqid((string)time(), true)))
            . '#auth_redirect';
        Log::debug('Client::getCode(Url)' . $url);

        header('HTTP/1.1 301 Moved Permanently');
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
     * @param string $code 用于换取access_token的code
     * @param bool   $cache
     *
     * @return array|mixed|\think\response\Redirect
     * @throws \Psr\SimpleCache\InvalidArgumentException
     */
    public function getAccessToken(string $appid, string $secret, string $code, $cache = true) {
        if (empty($appid)) {
            return array();
        }
        if (empty($secret)) {
            return array();
        }

        $cacheKey = 'sso.client:access_token:appid:' . $appid . ':secret:' . $secret;

        if ($this->getCache()->has($cacheKey) && $cache) {
            $token = $this->getCache()->get($cacheKey);
            if (!empty($token) && !empty($token['openid']) && !empty($token['access_token'])) {
                return $token;
            }
        }

        if (empty($code)) {
            return array();
        }

        $url = Config::get('auth.host', Authorize::$host)
            . '/auth.php/oauth2/access_token?appid=' . $appid . '&secret=' . $secret . '&code=' . $code . '&grant_type=authorization_code';

        Log::debug('Client::getAccessToken(Url)' . $url);

        $curl = Curl::getInstance(true)
                    ->get($url, 'json');
        $result = $curl->toArray();

        switch ($curl->getResponseCode()) {
            case 200:
                if (!empty($result) && !empty($result['data']) && !empty($result['code'])) {
                    switch ($result['code']) {
                        case 200:
                            $token = $result['data'];
                            if (empty($token)) {
                                Log::error('Client::getAccessToken(Token is null)' . json_encode($result, JSON_UNESCAPED_UNICODE));
                            } elseif (empty($token['openid'])) {
                                Log::error('Client::getAccessToken(Token.openid is null)' . json_encode($result, JSON_UNESCAPED_UNICODE));
                            } elseif (empty($token['access_token'])) {
                                Log::error('Client::getAccessToken(Token.access_token is null)' . json_encode($result, JSON_UNESCAPED_UNICODE));
                            } else {
                                return $token;
                            }
                            break;
                        default:
                            Log::error('Client::getAccessToken(Invalid code, get code again)' . json_encode($result, JSON_UNESCAPED_UNICODE));

                            return $this->getCode(
                                $appid,
                                Request::url(true),
                                'code',
                                'auth_union',
                                md5(uniqid((string)time(), true))
                            );
                            break;
                    }
                }
                Log::error('Client::getAccessToken(Responsive Exception)' . json_encode($result, JSON_UNESCAPED_UNICODE));
                break;
            default:
                Log::error(
                    'Client::getAccessToken(Request Exception)' . $code . ' ' . $curl->getError() . ' ' . json_encode($curl->getInfo(), JSON_UNESCAPED_UNICODE)
                );
                break;
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
     * @return array
     * @link    https://developers.weixin.qq.com/doc/offiaccount/OA_Web_Apps/Wechat_webpage_authorization.html#2
     */
    public function refreshToken(string $appid, string $refresh_token): array {
        if (empty($appid)) {
            return array();
        }
        if (empty($refresh_token)) {
            $refresh_token = Request::get('refresh_token');
        }
        $url = Config::get('auth.host', Authorize::$host)
            . '/auth.php/oauth2/refresh_token?appid=' . $appid . '&grant_type=refresh_token&refresh_token=' . $refresh_token;

        Log::debug('Client::refreshToken(Url)' . $url);

        $token = Curl::getInstance(true)
                     ->get($url)
                     ->toArray();

        if (!empty($token) && !empty($token['access_token']) && !empty($token['refresh_token'])) {
            return $token;
        }

        return array();
    }

    /**
     * 4、第四步：拉取用户信息(需scope为 auth_userinfo)
     *
     * @param string $access_token 网页授权接口调用凭证,注意：此access_token与基础支持的access_token不同
     * @param string $openid       用户的唯一标识
     * @param string $lang         返回国家地区语言版本，zh_CN 简体，zh_TW 繁体，en 英语
     *
     * @return array 微信用户信息数组
     * @throws \Psr\SimpleCache\InvalidArgumentException
     * @link https://developers.weixin.qq.com/doc/offiaccount/OA_Web_Apps/Wechat_webpage_authorization.html#3
     */
    public function getUserInfo(string $access_token, string $openid, string $lang = 'zh_CN'): array {
        if (empty($access_token) || empty($openid)) {
            $token = $this->getAccessToken(Config::get('auth.appid'), Config::get('auth.appsecret'), Request::get('code'));

            if (!empty($token) && !empty($token['access_token'])) {
                $access_token = $token['access_token'];
            }

            if (!empty($token) && !empty($token['openid'])) {
                $openid = $token['openid'];
            }
        }
        if (empty($lang)) {
            $lang = Config::get('lang.default_lang', 'zh_CN');
        }

        $url = Config::get('auth.host', Authorize::$host)
            . '/auth.php/oauth2/userinfo?access_token=' . $access_token . '&openid=' . $openid . '&lang=' . $lang;

        Log::debug('Client::getUserInfo(Url)' . $url);

        $curl = Curl::getInstance(true)
                    ->get($url, 'json');

        $result = $curl->toArray();
        $code = $curl->getResponseCode();

        // @todo 响应结果解析有待优化
        switch ($code) {
            case 200:
                if (!empty($result) && !empty($result['code']) && !empty($result['data'])) {
                    switch ($result['code']) {
                        case 200:
                            $userinfo = $result['data'];
                            if (empty($userinfo)) {
                                Log::error('Client::getUserInfo(UserInfo is null)' . json_encode($result, JSON_UNESCAPED_UNICODE));
                            } elseif (!isset($userinfo['openid']) || empty($userinfo['openid'])) {
                                Log::error('Client::getUserInfo(UserInfo.openid is null)' . json_encode($result, JSON_UNESCAPED_UNICODE));
                            } elseif (!isset($userinfo['nickname']) || empty($userinfo['nickname'])) {
                                Log::error('Client::getUserInfo(UserInfo.nickname is null)' . json_encode($result, JSON_UNESCAPED_UNICODE));
                            } elseif (!isset($userinfo['sex']) || empty($userinfo['sex'])) {
                                Log::error('Client::getUserInfo(UserInfo.sex is null)' . json_encode($result, JSON_UNESCAPED_UNICODE));
                            } elseif (!isset($userinfo['avatar']) || empty($userinfo['avatar'])) {
                                Log::error('Client::getUserInfo(UserInfo.avatar is null)' . json_encode($result, JSON_UNESCAPED_UNICODE));
                            } else {
                                return $userinfo;
                            }
                            break;
                    }
                }
                Log::error('Client::getUserInfo(Responsive Exception)' . json_encode($result, JSON_UNESCAPED_UNICODE));
                break;
            default:
                Log::error(
                    'Client::getUserInfo(Request Exception)' . $code . ' ' . $curl->getError() . ' ' . json_encode($curl->getInfo(), JSON_UNESCAPED_UNICODE)
                );
                break;
        }

        return array();
    }

    /**
     * 5、附：检验授权凭证（access_token）是否有效
     *{ "errcode":0,"errmsg":"ok"}
     *
     * @param string $access_token 网页授权接口调用凭证,注意：此access_token与基础支持的access_token不同
     * @param string $openid       用户的唯一标识
     *
     * @return bool
     * @throws \Psr\SimpleCache\InvalidArgumentException
     * @link https://developers.weixin.qq.com/doc/offiaccount/OA_Web_Apps/Wechat_webpage_authorization.html#4
     */
    public function verifyToken(string $access_token, string $openid): bool {
        if (empty($access_token) || empty($openid)) {
            $token = $this->getAccessToken(Config::get('auth.appid'), Config::get('auth.appsecret'), Request::get('code'));

            if (!empty($token) && !empty($token['access_token'])) {
                $access_token = $token['access_token'];
            }

            if (!empty($token) && !empty($token['openid'])) {
                $openid = $token['openid'];
            }
        }
        $url = Config::get('auth.host', Authorize::$host) .
            '/auth.php/oauth2/verify_token?access_token=' . $access_token . '&openid=' . $openid;
        $result = Curl::getInstance(true)
                      ->get($url, 'json')
                      ->toArray();
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
    public function authentication(
        string $appid, string $redirect_uri, string $response_type = 'code', string $scope = 'auth_base', $access_type = 'offline', string $state = ''
    ) {
        $url = Config::get('auth.host', Authorize::$host)
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