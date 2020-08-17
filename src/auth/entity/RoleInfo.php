<?php

declare (strict_types=1);

namespace mark\auth\entity;

use think\facade\Request;
use think\facade\Config;
use think\facade\Cache;
use mark\http\Curl;

final class RoleInfo {

    /**
     * 获取角色列表
     *
     * @param string $appid
     * @param string $poolid
     * @param bool   $cache
     *
     * @return array
     */
    public static function getRoleList(string $appid, string $poolid, $cache = true) {
        if (empty($appid)) {
            $appid = Request::param('appid', Config::get("auth.appid"));
        }

        if (empty($poolid)) {
            $poolid = Request::param('poolid', Config::get("auth.poolid"));
        }

        $cacheKey = 'channel:rolelist:' . ':appid:' . $appid . ':poolid:' . $poolid;

        if (Cache::has($cacheKey) && $cache) {
            $roles = Cache::get($cacheKey);
            if (!empty($roles)) {
                // return $roles;
            }
        }

        $result = Curl::getInstance(true)
                      ->get(Config::get('auth.host', 'https://auth.tianfu.ink') . '/api.php/role/rolelist', 'json')
                      ->appendData('appid', $appid)
                      ->appendData('poolid', $poolid)
                      ->appendData('cache', $cache ? 1 : 0)
                      ->toArray();

        if (!empty($result) && !empty($result['code']) && $result['code'] == 200 && !empty($result['data'])) {
            if ($cache) {
                // Cache::set($cacheKey, $result['data'], Config::get('session.expire', 1440));
                // $this->authority->$cache->set($cacheKey, $result, Config::get('session.expire', 1440));
            }

            return $result['data'];
        }
        // $this->authority->logcat('error', 'Channel::getWorkspace(Data Not Found Exception)' . $cacheKey . ' ' . json_encode($result, JSON_UNESCAPED_UNICODE));
        Cache::delete($cacheKey);

        return array();
    }

    /**
     * 获取角色详情
     *
     * @param string $appid
     * @param string $poolid
     * @param int    $roleid
     * @param bool   $cache
     *
     * @return array
     */
    public static function getRoleInfo(string $appid, string $poolid, $roleid = 404, $cache = true) {
        if (empty($appid)) {
            $appid = Request::param('appid', Config::get("auth.appid"));
        }

        if (empty($poolid)) {
            $poolid = Request::param('poolid', Config::get("auth.poolid"));
        }

        $cacheKey = 'channel:roleinfo:' . ':appid:' . $appid . ':poolid:' . $poolid . ':roleid:' . $roleid;

        if (Cache::has($cacheKey) && $cache) {
            $roles = Cache::get($cacheKey);
            if (!empty($roles)) {
                // return $roles;
            }
        }

        $result = Curl::getInstance(true)
                      ->get(Config::get('auth.host', 'https://auth.tianfu.ink') . '/api.php/role/roleinfo', 'json')
                      ->appendData('appid', $appid)
                      ->appendData('poolid', $poolid)
                      ->appendData('roleid', $roleid)
                      ->appendData('cache', $cache ? 1 : 0)
                      ->toArray();

        if (!empty($result) && !empty($result['code']) && $result['code'] == 200 && !empty($result['data'])) {
            if ($cache) {
                // Cache::set($cacheKey, $result['data'], Config::get('session.expire', 1440));
                // $this->authority->$cache->set($cacheKey, $result, Config::get('session.expire', 1440));
            }

            return $result['data'];
        }
        // $this->authority->logcat('error', 'Channel::getWorkspace(Data Not Found Exception)' . $cacheKey . ' ' . json_encode($result, JSON_UNESCAPED_UNICODE));
        Cache::delete($cacheKey);

        return array();
    }

}