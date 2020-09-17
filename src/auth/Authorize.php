<?php

declare (strict_types=1);

namespace mark\auth;

use think\facade\Session;
use think\facade\Config;
use think\facade\Request;
use Psr\SimpleCache\CacheInterface;

final class Authorize {

    public static $expiretime = 'expiretime';
    public static $login      = 'login';
    public static $isLogin    = 'isLogin';
    public static $isAdmin    = 'isAdmin';
    public static $isTesting  = 'isTesting';
    public static $isManager  = 'isManager';
    public static $isOrganize = 'isOrganize';

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
     * @var \mark\auth\Client
     */
    private static $client;

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
        if ($level == 'master') {
            return redirect(Config('auth.host') . '/auth.php/login/login?callback=' . urlencode(Request::url(true)));
        }

        return self::getClient(true)->request($scope);
    }

    public static function getClient(bool $complete = false) {
        if (empty(self::$client) || !self::$client instanceof Client || $complete) {
            self::$client = new Client(Authorize::getInstance());
        }

        return self::$client;
    }

    /**
     * @var CacheInterface
     */
    private static $cache;

    /**
     * @param \Psr\SimpleCache\CacheInterface $cache
     */
    public static function setCache(CacheInterface $cache) {
        self::$cache = $cache;
    }

    /**
     * @return \Psr\SimpleCache\CacheInterface
     */
    public static function getCache() {
        return self::$cache;
    }

    /**
     * 检测用户是否已经登录
     * 已登录为True
     * 未登录为False
     *
     * @return bool
     */
    public static function isLogin($value = array()) {
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
    public static function isUnion($value = array()) {
        return self::isLogin()
            && Session::has('union') && !empty(Session::get('union'))
            && Session::get('union.unionid', 0) != 0
            && Session::get('union.uid', 0) != 0
            && Session::get('union.poolid', 1) == Config::get('auth.poolid', 0)
            && Session::get('union.roleid', 0) != 0
            && Session::get('union.status', 0) != 0;
    }

    /**
     * 校验是否为组织
     *
     * @return bool
     */
    public static function isOrganize($value = array()) {
        return self::isUnion()
            && Session::has('union') && !empty(Session::get('union'))
            && Session::get('union.unionid', 0) != 0
            && Session::get('union.uid', 0) != 0
            && Session::get('union.poolid', 1) == Config::get('auth.poolid', 0)
            && Session::get('union.roleid', 0) != 0
            && Session::get('union.status', 0) != 0
            && Session::get('union.organize')
            && Session::get('union.organize.orgid', 0) != 0;
    }

    /**
     * 校验是否为门店
     *
     * @return bool
     */
    public static function isStore($value = array()) {
        return self::isUnion()
            && Session::has('union') && !empty(Session::get('union'))
            && Session::get('union.unionid', 0) != 0
            && Session::get('union.uid', 0) != 0
            && Session::get('union.poolid', 1) == Config::get('auth.poolid', 0)
            && Session::get('union.roleid', 0) != 0
            && Session::get('union.status', 0) != 0
            && Session::get('union.store') && Session::get('union.store.storeid', 0) != 0;
    }

    /**
     * 验证是否为系统管理员
     * 管理员为True
     * 其它人为False
     *
     * @param array $value
     *
     * @return bool
     */
    public static function isAdmin($value = array()) {
        return self::isLogin() && Session::get(self::$isAdmin, 0) === 1
            && (
                Session::get('gid', 200) <= 10 ||
                Session::get('union.gid', 200) <= 10 ||
                Session::get('union.guid', 200) <= 10 ||

                Session::get('union.roleid', 200) <= 10
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
    public static function isManager($value = array()) {
        return self::isLogin() && Session::get(self::$isAdmin, 0) === 1
            && (
                Session::get('gid', 200) <= 10 ||
                Session::get('union.gid', 200) <= 10 ||
                Session::get('union.guid', 200) <= 10 ||

                Session::get('union.roleid', 200) <= 10
            );
    }

    /**
     * 验证是否为测试员
     * 测试员为True
     * 其它人为False
     *
     * @return bool
     */
    public static function isTesting($value = array()) {
        return self::isLogin() && Session::get(self::$isTesting, 0) === 1 && Session::get('union.roleid', 200) === 340;
    }

    /**
     * 验证是否过期
     * 已过期为True
     * 未过期为False
     *
     * @return bool
     */
    public static function isExpire($value = array()) {
        return Session::get(self::$expiretime, 0) < time();
    }

    /**
     * 验证是否有权限
     * PermissionID 权限值
     *
     * @param $permissionid
     */
    public static function hasPermission($permission = null) {

    }

}
