<?php

declare (strict_types=1);

namespace mark\auth\entity;

use think\facade\Config;
use think\facade\Cache;
use mark\http\Curl;
use mark\auth\Authorize;
use mark\response\Responsive;

final class UnionInfo {

    /**
     * 获取授权详情
     *
     * @param string $openid
     * @param        $unionid
     * @param string $appid
     * @param string $poolid
     * @param bool   $cache
     *
     * @return array
     */
    public static function getUnionInfo(string $openid, $unionid, string $appid, string $poolid, $cache = true): array {
        if (empty($openid)) {
            return Responsive::display('', 412, '', '无效的授权ID', 'origin');
        }
        if (empty($unionid)) {
            return Responsive::display('', 412, '', '无效的联合授权ID', 'origin');
        }
        if (empty($appid)) {
            return Responsive::display('', 412, '', '无效的AppID', 'origin');
        }
        if (empty($poolid)) {
            return Responsive::display('', 412, '', '无效的PoolID', 'origin');
        }

        $cacheKey = 'AuthUnion:unioninfo:appid:' . $appid . ':poolid:' . $poolid . ':unionid:' . $unionid;
        if (Cache::has($cacheKey) && $cache) {
            // $result = $this->authority->cache->get($cacheKey);
            $union = Cache::get($cacheKey);
            if (!empty($union)) {
                // return $union;
            }
        }

        $result = Curl::getInstance(true)
                      ->get(Config::get('auth.host', Authorize::$host) . '/api.php/union/union_info', 'json')
                      ->appendData('openid', $openid)
                      ->appendData('unionid', $unionid)
                      ->appendData('poolid', $poolid)
                      ->appendData('appid', $appid)
                      ->appendData('cache', $cache)
                      ->toArray();

        if (!empty($result) && !empty($result['code']) && $result['code'] == 200 && !empty($result['data'])) {
            if ($cache) {
                // $this->authority->$cache->set($cacheKey, $result, Config::get('session.expire', 1440));
                // Cache::set($cacheKey, $result, Config::get('session.expire', 1440));
            }

            return $result;
        }
        // $this->authority->logcat('error', 'RoleInfo::find(Data Not Found Exception)' . $cacheKey . ' ' . json_encode($result, JSON_UNESCAPED_UNICODE));
        Cache::delete($cacheKey);

        return $result;
    }

    /**
     * 获取授权列表
     *
     * @param string $openid
     * @param string $appid
     * @param string $poolid
     * @param bool   $cache
     *
     * @return array
     */
    public static function getUnionList(string $openid, string $appid, string $poolid, $cache = true): array {
        if (empty($openid)) {
            return Responsive::display('', 412, '', '无效的授权ID', 'origin');
        }
        if (empty($appid)) {
            return Responsive::display('', 412, '', '无效的AppID', 'origin');
        }
        if (empty($poolid)) {
            return Responsive::display('', 412, '', '无效的PoolID', 'origin');
        }

        $cacheKey = 'AuthUnion:unionlist:appid:' . $appid . ':poolid:' . $poolid;
        if (Cache::has($cacheKey) && $cache) {
            // $result = $this->authority->cache->get($cacheKey);
            $unions = Cache::get($cacheKey);
            if (!empty($unions)) {
                // TODO：临时关闭缓存
                // return $unions;
            }
        }

        $result = Curl::getInstance(true)
                      ->get(Config::get('auth.host', Authorize::$host) . '/api.php/union/union_select', 'json')
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

            return $result;
        }
        // $this->authority->logcat('error', 'union::getunionList(Data Not Found Exception)' . $cacheKey . ' ' . json_encode($result, JSON_UNESCAPED_UNICODE));
        Cache::delete($cacheKey);

        return $result;
    }

    /**
     * 添加授权信息
     *
     * @param string $openid
     * @param array  $union
     * @param string $appid
     * @param string $poolid
     *
     * @return array
     */
    public static function createUnion(string $openid, array $union, string $appid, string $poolid): array {
        if (empty($openid)) {
            return Responsive::display('', 412, '', '无效的授权ID', 'origin');
        }
        if (empty($union)) {
            return Responsive::display('', 412, '', '无效的授权信息', 'origin');
        }
        if (empty($appid)) {
            return Responsive::display('', 412, '', '无效的AppID', 'origin');
        }
        if (empty($poolid)) {
            return Responsive::display('', 412, '', '无效的PoolID', 'origin');
        }

        $result = Curl::getInstance(true)
                      ->post(Config::get('auth.host', Authorize::$host) . '/api.php/union/union_create')
                      ->appendData('openid', $openid)
                      ->appendData('union', $union)
                      ->appendData('appid', $appid)
                      ->appendData('poolid', $poolid)
                      ->toArray();

        // $this->authority->logcat('error', 'UnionInfo::insert(Data Not Found Exception)' . $cacheKey . ' ' . json_encode($result, JSON_UNESCAPED_UNICODE));

        return $result;
    }

    /**
     * 更新授权信息
     *
     * @param string $openid
     * @param        $unionid
     * @param array  $union
     * @param string $appid
     * @param string $poolid
     *
     * @return array
     */
    public static function updateUnion(string $openid, $unionid, array $union, string $appid, string $poolid): array {
        if (empty($openid)) {
            return Responsive::display('', 412, '', '无效的授权ID', 'origin');
        }
        if (empty($unionid)) {
            return Responsive::display('', 412, '', '无效的联合授权ID', 'origin');
        }
        if (empty($union)) {
            return Responsive::display('', 412, '', '无效的授权信息', 'origin');
        }
        if (empty($appid)) {
            return Responsive::display('', 412, '', '无效的AppID', 'origin');
        }
        if (empty($poolid)) {
            return Responsive::display('', 412, '', '无效的PoolID', 'origin');
        }

        $result = Curl::getInstance(true)
                      ->post(Config::get('auth.host', Authorize::$host) . '/api.php/union/union_update')
                      ->appendData('openid', $openid)
                      ->appendData('unionid', $unionid)
                      ->appendData('union', $union)
                      ->appendData('poolid', $poolid)
                      ->appendData('appid', $appid)
                      ->toArray();

        // $this->authority->logcat('error', 'UnionInfo::update(Data Not Found Exception)' . $cacheKey . ' ' . json_encode($result, JSON_UNESCAPED_UNICODE));

        return $result;
    }

    /**
     * 删除授权信息
     *
     * @param string $openid
     * @param        $unionid
     * @param string $appid
     * @param string $poolid
     *
     * @return array
     */
    public static function deleteUnion(string $openid, $unionid, string $appid, string $poolid): array {
        if (empty($openid)) {
            return Responsive::display('', 412, '', '无效的授权ID', 'origin');
        }
        if (empty($unionid)) {
            return Responsive::display('', 412, '', '无效的联合授权ID', 'origin');
        }
        if (empty($appid)) {
            return Responsive::display('', 412, '', '无效的AppID', 'origin');
        }
        if (empty($poolid)) {
            return Responsive::display('', 412, '', '无效的PoolID', 'origin');
        }
        $result = Curl::getInstance(true)
                      ->post(Config::get('auth.host', Authorize::$host) . '/api.php/union/union_delete')
                      ->appendData('unionid', $unionid)
                      ->appendData('openid', $openid)
                      ->appendData('poolid', $poolid)
                      ->appendData('appid', $appid)
                      ->toArray();

        // $this->authority->logcat('error', 'UnionInfo::delete(Data Not Found Exception)' . $cacheKey . ' ' . json_encode($result, JSON_UNESCAPED_UNICODE));

        return $result;
    }

}