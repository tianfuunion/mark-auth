<?php

    declare (strict_types=1);

    namespace mark\auth;

    use think\facade\Config;
    use think\facade\Request;
    use think\response\Redirect;

    class AuthUnion
    {

        /**
         * 用户授权校验并请求
         *
         * @param bool $complete
         * @param string $response
         * @param string $scope
         * @param string $access_type
         * @param int $state
         *
         * @return Redirect
         * @deprecated
         * @see Authorize::authentication()
         */
        public static function request($complete = false, $response = 'code', $scope = 'snsapi_base', $access_type = 'offline', $state = 0)
        {

            $url = Config('auth.host') . '/auth.php/authorize/choice'
            // $url = Config::get('auth.host') . '/auth.php/oauth2/authorize'
            . '?appid=' . Config('auth.appid')
            . '&redirect_uri=' . urlencode(Request::url($complete))
            . '&response_type=' . $response
            . '&scope=openid'
            . '&scope=' . ($scope === 'snsapi_base' ? 'snsapi_base' : 'snsapi_userinfo')
            . '&access_type=' . $access_type
            . '&state=' . $state !== 0 ? $state : md5(uniqid((string)time(), true));

            header('Location:' . $url);

            return redirect($url, 401);
        }

    }