<?php

declare (strict_types=1);

namespace mark\auth;

use think\facade\Session;
use think\facade\Config;
use think\facade\Request;
use mark\system\Os;
use mark\auth\sso\driver\WeChat;
use mark\auth\sso\driver\AliPay;
use mark\auth\sso\driver\DingTalk;

final class Authorize {

    public static $expiretime = 'expiretime';
    public static $login      = 'login';
    public static $isLogin    = 'isLogin';
    public static $isAdmin    = 'isAdmin';
    public static $isTesting  = 'isTesting';

    private function __construct() {
    }

    private static $instance;

    public static function getInstance() {
        if (self::$instance == null) {
            self::$instance = new self();
        }

        return self::$instance;
    }

    /**
     * 登录请求
     *
     * @param bool   $complete
     * @param string $scope
     *
     * @return \think\response\Redirect
     */
    public static function request($complete = true, $scope = 'auth_base') {
        $url = Config::get('auth.host') . '/auth.php/login/login?scope=' . $scope . '&callback=' . urlencode(Request::url($complete));
        header('Location:' . $url);

        return redirect($url);
    }

    /**
     * @var \mark\auth\Client
     */
    public static $client;

    /**
     * 权限验证分发器
     * 1、权限级别｛1登录、2会员、3管理员等｝
     *
     * @param string $level
     * @param string $scope
     *
     * @return array|bool|false|mixed|string|\think\response\Redirect
     */
    public static function dispenser($level = 'slave', $scope = '') {
        if ($level == 'master' && $scope != 'auth_union') {
            if (Os::isWeChat() && Config('auth.stores.wechat.status')) {
                $sso = new WeChat(Authorize::getInstance(), $level);

                return $sso->request($scope == 'snsapi_userinfo' ? 'snsapi_userinfo' : 'snsapi_base');
            }

            if (Os::isAliPay() && Config('auth.stores.alipay.status')) {
                $sso = new AliPay(Authorize::getInstance(), $level);

                return $sso->request($scope);
            }

            if (Os::isDingTalk() && Config('auth.stores.dingtalk.status')) {
                $sso = new DingTalk(Authorize::getInstance(), $level);

                return $sso->request($scope);
            }

            return redirect(Config('auth.host') . '/auth.php/login/login?callback=' . urlencode(Request::url(true)));
        }

        return self::getClient($level)->request($scope);
    }

    public static function getClient($level = 'slave') {
        if (empty(self::$client) || !self::$client instanceof Client) {
            self::$client = new Client(Authorize::getInstance(), $level);
        }

        return self::$client;
    }

    /**
     * 检测用户是否已经登录
     * 已登录为True
     * 未登录为False
     *
     * @return bool
     */
    public static function isLogin() {
        return
            Session::get(self::$login, 0) === 1
            && Session::get(self::$isLogin, 0) === 1
            && (Session::get('uuid', 0) !== 0 || Session::get('uid', 0) !== 0)
            && (Session::get('guid', 0) !== 0 || Session::get('gid', 0) !== 0)
            && !self::isExpire();
    }

    /**
     * 验证是否经验联合授权
     *
     * @TODO Union.Status 有待完善，具体有效数据
     * @return bool
     */
    public static function isUnion() {
        return self::isLogin()
            && Session::has('union') && !empty(Session::get('union'))
            && Session::get('union.unionid', 0) != 0
            && Session::get('union.uid', 0) != 0
            && Session::get('union.poolid', 1) == Config::get('auth.poolid', 0)
            && Session::get('union.roleid', 0) != 0
            && Session::get('union.status', 0) != 0;
    }

    /**
     * 验证是否为系统管理员
     * 管理员为True
     * 其它人为False
     *
     * @return bool
     */
    public static function isAdmin() {
        return self::isLogin() &&
            Session::get(self::$isAdmin, 0) === 1
            && (
                Session::get('gid', 100) <= 10 ||
                Session::get('union.gid', 100) <= 10 ||
                Session::get('union.guid', 100) <= 10 ||

                Session::get('union.roleid', 100) <= 10
            );
    }

    /**
     * 校验是否为管理者
     *
     * 管理者为True
     * 其它人为False
     *
     * @return bool
     */
    public static function isManager() {
        return self::isLogin() &&
            Session::get(self::$isAdmin, 0) === 1
            && (
                Session::get('gid', 100) <= 10 ||
                Session::get('union.gid', 100) <= 10 ||
                Session::get('union.guid', 100) <= 10 ||

                Session::get('union.roleid', 100) <= 10
            );
    }

    /**
     * 验证是否为测试员
     * 测试员为True
     * 其它人为False
     *
     * @return bool
     */
    public static function isTesting() {
        return self::isLogin() &&
            Session::get(self::$isTesting, 0) === 1 &&
            Session::get('union.roleid', 0) === 340;
    }

    /**
     * 验证是否过期
     * 已过期为True
     * 未过期为False
     *
     * @return bool
     */
    public static function isExpire() {
        return Session::get(self::$expiretime, 0) < time();
    }

    /**
     * 验证是否有权限
     * PermissionID 权限值
     *
     * @param $permissionid
     */
    public static function hasPermission($permissionid = null) {

    }

}
