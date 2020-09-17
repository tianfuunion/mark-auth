<?php

declare (strict_types=1);

namespace mark\auth\entity;

use think\facade\Config;
use think\facade\Cache;
use mark\http\Curl;

final class RoleInfo {

    /**
     * 获取角色详情
     *
     * @param        $id
     * @param string $openid
     * @param string $appid
     * @param string $poolid
     * @param bool   $cache
     *
     * @return array
     */
    public static function find($id, string $openid, string $appid, string $poolid, $cache = true): array {
        if (empty($id)) {
            return array();
        }
        if (empty($openid)) {
            return array();
        }
        if (empty($appid)) {
            return array();
        }
        if (empty($poolid)) {
            return array();
        }

        $cacheKey = 'AuthUnion:roleinfo:appid:' . $appid . ':poolid:' . $poolid . ':id:' . $id;
        if (Cache::has($cacheKey) && $cache) {
            // $result = $this->authority->cache->get($cacheKey);
            $role = Cache::get($cacheKey);
            if (!empty($role)) {
                // return $role;
            }
        }

        $result = Curl::getInstance(true)
                      ->get(Config::get('auth.host', 'https://auth.tianfu.ink') . '/api.php/role/role_info', 'json')
                      ->appendData('id', $id)
                      ->appendData('openid', $openid)
                      ->appendData('appid', $appid)
                      ->appendData('poolid', $poolid)
                      ->appendData('cache', $cache)
                      ->toArray();

        if (!empty($result) && !empty($result['code']) && $result['code'] == 200 && !empty($result['data'])) {
            if ($cache) {
                // $this->authority->$cache->set($cacheKey, $result, Config::get('session.expire', 1440));
                // Cache::set($cacheKey, $result, Config::get('session.expire', 1440));
            }

            return $result['data'];
        }
        // $this->authority->logcat('error', 'RoleInfo::getRoleInfo(Data Not Found Exception)' . $cacheKey . ' ' . json_encode($result, JSON_UNESCAPED_UNICODE));
        Cache::delete($cacheKey);

        return array();
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
    public static function select(string $openid, string $appid, string $poolid, $cache = true): array {
        if (empty($openid)) {
            return array();
        }
        if (empty($appid)) {
            return array();
        }
        if (empty($poolid)) {
            return array();
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
                      ->get(Config::get('auth.host', 'https://auth.tianfu.ink') . '/api.php/role/role_list', 'json')
                      ->appendData('openid', $openid)
                      ->appendData('appid', $appid)
                      ->appendData('poolid', $poolid)
                      ->appendData('cache', $cache)
                      ->toArray();

        if (!empty($result) && !empty($result['code']) && $result['code'] == 200 && !empty($result['data'])) {
            if ($cache) {
                // $this->authority->$cache->set($cacheKey, $result, Config::get('session.expire', 1440));
                // Cache::set($cacheKey, $result['data'], Config::get('session.expire', 1440));
            }

            return $result['data'];
        }
        // $this->authority->logcat('error', 'Role::getRoleList(Data Not Found Exception)' . $cacheKey . ' ' . json_encode($result, JSON_UNESCAPED_UNICODE));
        Cache::delete($cacheKey);

        return array();
    }

    /**
     * 添加角色信息
     *
     * @param array  $role
     * @param string $openid
     * @param string $appid
     * @param string $poolid
     *
     * @return int
     */
    public static function insert(array $role, string $openid, string $appid, string $poolid): int {
        if (empty($role)) {
            return 0;
        }
        if (empty($openid)) {
            return 0;
        }
        if (empty($appid)) {
            return 0;
        }
        if (empty($poolid)) {
            return 0;
        }

        $result = Curl::getInstance(true)
                      ->post(Config::get('auth.host', 'https://auth.tianfu.ink') . '/api.php/role/role_insert', 'json')
                      ->appendData('role', $role)
                      ->appendData('openid', $openid)
                      ->appendData('poolid', $poolid)
                      ->appendData('appid', $appid)
                      ->toArray();

        if (!empty($result) && !empty($result['code']) && $result['code'] == 200 && !empty($result['data'])) {

            return $result['data'];
        }

        // $this->authority->logcat('error', 'RoleInfo::getRoleInfo(Data Not Found Exception)' . $cacheKey . ' ' . json_encode($result, JSON_UNESCAPED_UNICODE));
        return 0;
    }

    /**
     * 更新角色信息
     *
     * @param        $id
     * @param string $openid
     * @param string $appid
     * @param string $poolid
     *
     * @return int
     */
    public static function update($id, string $openid, string $appid, string $poolid): int {
        if (empty($id)) {
            return 0;
        }
        if (empty($openid)) {
            return 0;
        }
        if (empty($appid)) {
            return 0;
        }
        if (empty($poolid)) {
            return 0;
        }

        $result = Curl::getInstance(true)
                      ->post(Config::get('auth.host', 'https://auth.tianfu.ink') . '/api.php/role/role_update', 'json')
                      ->appendData('id', $id)
                      ->appendData('openid', $openid)
                      ->appendData('poolid', $poolid)
                      ->appendData('appid', $appid)
                      ->toArray();

        if (!empty($result) && !empty($result['code']) && $result['code'] == 200 && !empty($result['data'])) {

            return $result['data'];
        }

        // $this->authority->logcat('error', 'RoleInfo::getRoleInfo(Data Not Found Exception)' . $cacheKey . ' ' . json_encode($result, JSON_UNESCAPED_UNICODE));
        return 0;
    }

    /**
     * 删除角色信息
     *
     * @param        $id
     * @param string $openid
     * @param string $appid
     * @param string $poolid
     *
     * @return int
     */
    public static function delete($id, string $openid, string $appid, string $poolid): int {
        if (empty($id)) {
            return 0;
        }
        if (empty($openid)) {
            return 0;
        }
        if (empty($appid)) {
            return 0;
        }
        if (empty($poolid)) {
            return 0;
        }

        $result = Curl::getInstance(true)
                      ->post(Config::get('auth.host', 'https://auth.tianfu.ink') . '/api.php/role/role_delete', 'json')
                      ->appendData('id', $id)
                      ->appendData('openid', $openid)
                      ->appendData('poolid', $poolid)
                      ->appendData('appid', $appid)
                      ->toArray();

        if (!empty($result) && !empty($result['code']) && $result['code'] == 200 && !empty($result['data'])) {
            return $result['data'];
        }

        // $this->authority->logcat('error', 'RoleInfo::getRoleInfo(Data Not Found Exception)' . $cacheKey . ' ' . json_encode($result, JSON_UNESCAPED_UNICODE));
        return 0;
    }

}