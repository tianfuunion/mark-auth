<?php

declare (strict_types=1);

namespace mark\src;

use think\facade\Session;
use think\facade\Config;
use think\facade\Request;
use think\response\Redirect;

class Authorize {

    public        $scope      = 'snsapi_base';
    public static $expiretime = 'expiretime';
    public static $login      = 'login';
    public static $isLogin    = 'isLogin';
    public static $isAdmin    = 'isAdmin';
    public static $isTesting  = 'isTesting';

    public function __construct($scope = '') {
        $this->scope = $scope === 'snsapi_userinfo' ? 'snsapi_userinfo' : 'snsapi_base';
    }

    /**
     * 登录请求
     *
     * @param bool   $complete
     * @param string $scope
     *
     * @return Redirect
     */
    public static function request($complete = true, $scope = '') {
        $url = Config::get('auth.host') . '/auth.php/login/login?backurl=' . urlencode(Request::url($complete));
        header('Location:' . $url);

        return redirect($url);
    }

    /**
     * 账号权限验证
     * 1、权限级别｛1登录、2会员、3管理员等｝
     *
     * @param null   $type
     * @param string $scope
     *
     * @param bool   $request
     *
     * @return array|bool|mixed
     */
    public static function dispenser($type = null, $scope = '', $request = true) {
        if (self::isLogin() && $request) {
            // 确保设置的有效期为正整数
            Session::set(self::$expiretime, time() + (int)round(abs(Config::get('auth.expire', 1440))));

            return true;
        }

        $level = $type == null ? Config::get('auth.level', 'slave') : $type;
        switch ($level) {
            case 'master':
                // 当前节点为主节点（账户节点）
                $Handle = new Server(new self($scope));
                break;
            case 'slave':
                // 当前节点为从节点（应用节点）
                $Handle = new Client(new self($scope));
                break;
            case 'cross':
                // 当前节点为应用节点，并且跨域
                $Handle = new Client(new self($scope));
                break;
            default:
                $Handle = new Client(new self($scope));
                break;
        }

        return $Handle->request();
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
            && Session::get('uid', 0) !== 0
            && Session::get('gid', 0) !== 0
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
            && Session::get('union', '') !== ''
            && Session::get('union.unionid', 0) !== 0
            && Session::get('union.uid', 0) !== 0
            // && Session::get('union.appid', 0) == Config::get('auth.appid', 1)
            && Session::get('union.poolid', 0) == Config::get('auth.poolid', 0)
            && Session::get('union.status', 0) !== 0
            && Session::get('union.roleid', 0) !== 0;
    }

    /**
     * 验证是否为管理员
     * 管理员为True
     * 其它人为False
     *
     * @return bool
     */
    public static function isAdmin() {
        return self::isLogin() &&
            Session::get(self::$isAdmin, 0) === 1 &&
            Session::get('gid', 100) <= 10;
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
