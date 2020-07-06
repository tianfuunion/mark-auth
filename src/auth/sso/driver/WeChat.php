<?php

    namespace mark\auth\sso\driver;

    use mark\auth\sso\Sso;
    use mark\http\Curl;
    use think\facade\Config;
    use think\facade\Request;
    use think\response\Redirect;

    class WeChat extends Sso
    {

        /**
         * 用户同意授权，获取code
         * Authorize constructor.
         *
         * @return array|bool|false|mixed|string
         */
        public function request()
        {
            // 1、第一步：用户同意授权，获取code
            if (!Request::has("code", "get", true)) {
                $result = $this->getCode(
                    Config::get('auth.stores.wechat.appid'),
                    Request::url(true),
                    Config::get('auth.stores.wechat.response_type', 'code'),
                    ($this->auth->scope === 'snsapi_userinfo' ? 'snsapi_userinfo' : 'snsapi_base'),
                    Config::get('auth.stores.wechat.state', md5(uniqid((string)time(), true)))
                );
                if ($result instanceof Redirect) {
                    return false;
                }

                return $result;
            }

            //2、第二步：通过code换取网页授权access_token
            $token = $this->getAccessToken(Config::get('auth.stores.wechat.appid'), Config::get('auth.stores.wechat.secret'), Request::get('code'));
            if (!$token || is_empty($token['access_token']) || is_empty($token['openid'])) {
                return $this->getCode(Request::url(true));
            }

            // TODO：这里已经获取到OpenId,可检查是否注册过，未注册则再申请UserInfo
            //4、第四步：拉取用户信息(需scope为 snsapi_userinfo)
            $userInfo = $this->getUserInfo($token['access_token'], $token['openid'], Config::get('lang.default_lang'));
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
         * @param string $appid 公众号的唯一标识
         * @param string $redirect_uri 授权后重定向的回调链接地址， 请使用 urlEncode 对链接进行处理
         * @param string $response_type 返回类型，请填写code
         * @param string $scope 应用授权作用域，snsapi_base （不弹出授权页面，直接跳转，只能获取用户openid），snsapi_userinfo （弹出授权页面，可通过openid拿到昵称、性别、所在地。并且， 即使在未关注的情况下，只要用户授权，也能获取其信息 ）
         * @param string $state 重定向后会带上state参数，开发者可以填写a-zA-Z0-9的参数值，最多128字节
         * @return mixed
         */
        public function getCode(string $appid, string $redirect_uri, string $response_type = 'code', string $scope = 'snsapi_base', string $state = '')
        {
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
        public function getAccessToken(string $appid, string $secret, string $code)
        {
            $url = 'https://api.weixin.qq.com/sns/oauth2/access_token' . '?appid=' . $appid . '&secret=' . $secret . '&code=' . $code . '&grant_type=authorization_code';

            $token = Curl::getInstance()->get($url)->toArray();

            if (!empty($token) && isset($token['errcode'])) {

                return false;
            }

            return $token;
        }

        /**
         * 3、第三步：刷新access_token（如果需要）
         * @explain JSON：
         *{
         * "access_token":"ACCESS_TOKEN",
         * "expires_in":7200,
         * "refresh_token":"REFRESH_TOKEN",
         * "openid":"OPENID",
         * "scope":"SCOPE"
         * }
         *
         * @param string $appid 公众号的唯一标识
         * @param string $refresh_token 填写通过access_token获取到的refresh_token参数
         * @return array|bool|false
         */
        public function refreshToken(string $appid, string $refresh_token)
        {
            $url = 'https://api.weixin.qq.com/sns/oauth2/refresh_token?appid=' . $appid . '&grant_type=refresh_token&refresh_token=' . $refresh_token;

            $token = Curl::getInstance()->get($url)->toArray();

            if (!is_empty($token) && is_empty($token['access_token']) && is_empty($token['refresh_token'])) {
                return $token;
            }
            return false;
        }
        /**
         *
         **
         * 通过code获取用户openid以及用户的微信号信息
         * 获取到用户的openid之后可以判断用户是否有数据，可以直接跳过获取access_token,也可以继续获取access_token
         * access_token每日获取次数是有限制的，access_token有时间限制，可以存储到数据库7200s. 7200s后access_token失效
         **/

        /**
         * 4 第四步：拉取用户信息(需scope为 snsapi_userinfo)
         *
         * @param string $access_token 网页授权接口调用凭证,注意：此access_token与基础支持的access_token不同
         * @param string $openid 用户的唯一标识
         * @param string $lang 返回国家地区语言版本，zh_CN 简体，zh_TW 繁体，en 英语
         * @return array|bool|false|string
         */
        public function getUserInfo(string $access_token, string $openid, string $lang = 'zh_CN')
        {
            $url = 'https://api.weixin.qq.com/sns/userinfo?access_token=' . $access_token . '&openid=' . $openid . '&lang=' . $lang;
            $userinfo = Curl::getInstance()->get($url)->toArray();

            if (isset($userinfo['errcode'])) {
                return false;
            }

            if (empty($userinfo) || empty($userinfo['openid']) || !isset($userinfo['openid'])) {
                return false;
            }

            return $userinfo;
        }

        /**
         * 5、附：检验授权凭证（access_token）是否有效
         *{ "errcode":0,"errmsg":"ok"}
         *
         * @param string $access_token 网页授权接口调用凭证,注意：此access_token与基础支持的access_token不同
         * @param string $openid 用户的唯一标识
         * @return bool
         * @link https://developers.weixin.qq.com/doc/offiaccount/OA_Web_Apps/Wechat_webpage_authorization.html#4
         */
        public function verifyToken(string $access_token, string $openid)
        {
            $url = 'https://api.weixin.qq.com/sns/auth?access_token=' . $access_token . '&openid=' . $openid;
            $result = Curl::getInstance()->get($url)->toArray();
            if ($result['errcode'] == 0) {
                return true;
            }
            return false;
        }
    }