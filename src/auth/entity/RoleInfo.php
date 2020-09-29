<?php

declare (strict_types=1);

namespace mark\auth\entity;

use think\facade\Config;
use think\facade\Cache;
use mark\http\Curl;
use mark\auth\Authorize;
use mark\response\Responsive;

final class RoleInfo {

    public static $level = array(
        'system'   => array('title' => '系统级', 'name' => 'system', 'describe' => '收发通知，计划定时任务执行，机器人'),
        'admin'    => array('title' => '管理级', 'name' => '', 'describe' => '超级管理员'),
        'testing'  => array('title' => '测试级', 'name' => '', 'describe' => '设计，开发，测试，维护'),
        'manager'  => array('title' => '管理级', 'name' => '', 'describe' => '平台管理员'),
        'organize' => array('title' => '组织级', 'name' => '', 'describe' => '组织级别，法人'),
        'pool'     => array('title' => '用户池级', 'name' => '', 'describe' => '用户池级，开放平台审核员'),
        'app'      => array('title' => '应用级', 'name' => '', 'describe' => '应用管理员'),
        'member'   => array('title' => '会员级', 'name' => '', 'describe' => '付费会员，'),
        'user'     => array('title' => '用户级', 'name' => '', 'describe' => '一般用户'),

        'default'  => array('title' => '默认', 'name' => 'default'),
        'public'   => array('title' => '公开', 'name' => 'public'),
        'proteced' => array('title' => '保护', 'name' => 'proteced'),
        'private'  => array('title' => '私有', 'name' => 'private'),
        'final'    => array('title' => '最终', 'name' => 'final'),
        'static'   => array('title' => '静态', 'name' => 'static'),
        'abstract' => array('title' => '抽象', 'name' => 'abstract'),
    );

    /**
     * 获取角色详情
     *
     * @param string $openid
     * @param        $roleid
     * @param string $appid
     * @param string $poolid
     * @param bool   $cache
     *
     * @return array
     */
    public static function getRoleInfo(string $openid, $roleid, string $appid, string $poolid, $cache = true): array {
        if (empty($openid)) {
            return Responsive::display('', 412, '', '无效的授权ID', 'origin');
        }
        if (empty($roleid)) {
            return Responsive::display('', 412, '', '无效的角色ID', 'origin');
        }
        if (empty($appid)) {
            return Responsive::display('', 412, '', '无效的AppID', 'origin');
        }
        if (empty($poolid)) {
            return Responsive::display('', 412, '', '无效的PoolID', 'origin');
        }
        $cacheKey = 'AuthUnion:roleinfo:appid:' . $appid . ':poolid:' . $poolid . ':roleid:' . $roleid;
        if (Cache::has($cacheKey) && $cache) {
            // $result = $this->authority->cache->get($cacheKey);
            $role = Cache::get($cacheKey);
            if (!empty($role)) {
                // return $role;
            }
        }

        $result = Curl::getInstance(true)
                      ->get(Config::get('auth.host', Authorize::$host) . '/api.php/role/role_info', 'json')
                      ->appendData('openid', $openid)
                      ->appendData('roleid', $roleid)
                      ->appendData('appid', $appid)
                      ->appendData('poolid', $poolid)
                      ->appendData('cache', $cache)
                      ->toArray();

        if (!empty($result) && !empty($result['code']) && $result['code'] == 200 && !empty($result['data'])) {
            if ($cache) {
                // $this->authority->$cache->set($cacheKey, $result, Config::get('session.expire', 1440));
                // Cache::set($cacheKey, $result, Config::get('session.expire', 1440));
            }

            return $result;
        }
        // $this->authority->logcat('error', 'RoleInfo::getRoleInfo(Data Not Found Exception)' . $cacheKey . ' ' . json_encode($result, JSON_UNESCAPED_UNICODE));
        Cache::delete($cacheKey);

        return $result;
    }

    /**
     * 获取角色列表
     *
     * @param string $openid
     * @param string $appid
     * @param string $poolid
     * @param bool   $cache
     *
     * @return array
     */
    public static function getRoleList(string $openid, string $appid, string $poolid, $cache = true): array {
        if (empty($openid)) {
            return Responsive::display('', 412, '', '无效的授权ID', 'origin');
        }
        if (empty($appid)) {
            return Responsive::display('', 412, '', '无效的AppID', 'origin');
        }
        if (empty($poolid)) {
            return Responsive::display('', 412, '', '无效的PoolID', 'origin');
        }

        $cacheKey = 'AuthUnion:rolelist:appid:' . $appid . ':poolid:' . $poolid;
        if (Cache::has($cacheKey) && $cache) {
            // $result = $this->authority->cache->get($cacheKey);
            $roles = Cache::get($cacheKey);
            if (!empty($roles)) {
                // TODO：临时关闭缓存
                // return $roles;
            }
        }

        $result = Curl::getInstance(true)
                      ->get(Config::get('auth.host', Authorize::$host) . '/api.php/role/role_list', 'json')
                      ->appendData('openid', $openid)
                      ->appendData('appid', $appid)
                      ->appendData('poolid', $poolid)
                      ->appendData('cache', $cache)
                      ->toArray();

        if (!empty($result) && !empty($result['code']) && $result['code'] == 200 && !empty($result['data'])) {
            if ($cache) {
                // $this->authority->$cache->set($cacheKey, $result, Config::get('session.expire', 1440));
                Cache::set($cacheKey, $result, Config::get('session.expire', 1440));
            }

            return $result;
        }
        // $this->authority->logcat('error', 'Role::getRoleList(Data Not Found Exception)' . $cacheKey . ' ' . json_encode($result, JSON_UNESCAPED_UNICODE));
        Cache::delete($cacheKey);

        return $result;
    }

    /**
     * 添加角色信息
     *
     * @param string $openid
     * @param array  $role
     * @param string $appid
     * @param string $poolid
     *
     * @return array
     */
    public static function createRole(string $openid, array $role, string $appid, string $poolid): array {
        if (empty($openid)) {
            return Responsive::display('', 412, '', '无效的授权ID', 'origin');
        }
        if (empty($role)) {
            return Responsive::display('', 412, '', '无效的角色信息', 'origin');
        }
        if (empty($appid)) {
            return Responsive::display('', 412, '', '无效的AppID', 'origin');
        }
        if (empty($poolid)) {
            return Responsive::display('', 412, '', '无效的PoolID', 'origin');
        }
        $result = Curl::getInstance(true)
                      ->post(Config::get('auth.host', Authorize::$host) . '/api.php/role/role_create')
                      ->appendData('role', $role)
                      ->appendData('openid', $openid)
                      ->appendData('poolid', $poolid)
                      ->appendData('appid', $appid)
                      ->toArray();

        // $this->authority->logcat('error', 'RoleInfo::getRoleInfo(Data Not Found Exception)' . $cacheKey . ' ' . json_encode($result, JSON_UNESCAPED_UNICODE));
        return $result;
    }

    /**
     * 更新角色信息
     *
     * @param string $openid
     * @param        $roleid
     * @param array  $role
     * @param string $appid
     * @param string $poolid
     *
     * @return array
     */
    public static function updateRole(string $openid, $roleid, array $role, string $appid, string $poolid): array {
        if (empty($openid)) {
            return Responsive::display('', 412, '', '无效的授权ID', 'origin');
        }
        if (empty($roleid)) {
            return Responsive::display('', 412, '', '无效的角色ID', 'origin');
        }
        if (empty($role)) {
            return Responsive::display('', 412, '', '无效的角色信息', 'origin');
        }
        if (empty($appid)) {
            return Responsive::display('', 412, '', '无效的AppID', 'origin');
        }
        if (empty($poolid)) {
            return Responsive::display('', 412, '', '无效的PoolID', 'origin');
        }

        $result = Curl::getInstance(true)
                      ->post(Config::get('auth.host', Authorize::$host) . '/api.php/role/role_update')
                      ->appendData('roleid', $roleid)
                      ->appendData('role', $role)
                      ->appendData('openid', $openid)
                      ->appendData('poolid', $poolid)
                      ->appendData('appid', $appid)
                      ->toArray();

        // $this->authority->logcat('error', 'RoleInfo::getRoleInfo(Data Not Found Exception)' . $cacheKey . ' ' . json_encode($result, JSON_UNESCAPED_UNICODE));
        return $result;
    }

    /**
     * 删除角色信息
     *
     * @param        $roleid
     * @param string $openid
     * @param string $appid
     * @param string $poolid
     *
     * @return array
     */
    public static function deleteRole(string $openid, $roleid, string $appid, string $poolid): array {
        if (empty($openid)) {
            return Responsive::display('', 412, '', '无效的授权ID', 'origin');
        }
        if (empty($roleid)) {
            return Responsive::display('', 412, '', '无效的角色ID', 'origin');
        }
        if (empty($appid)) {
            return Responsive::display('', 412, '', '无效的AppID', 'origin');
        }
        if (empty($poolid)) {
            return Responsive::display('', 412, '', '无效的PoolID', 'origin');
        }

        $result = Curl::getInstance(true)
                      ->post(Config::get('auth.host', Authorize::$host) . '/api.php/role/role_delete')
                      ->appendData('roleid', $roleid)
                      ->appendData('openid', $openid)
                      ->appendData('poolid', $poolid)
                      ->appendData('appid', $appid)
                      ->toArray();

        return $result;
    }

}