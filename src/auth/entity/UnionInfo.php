<?php

declare (strict_types=1);

namespace mark\auth\entity;

use think\facade\Config;
use think\facade\Cache;
use mark\http\Curl;

final class UnionInfo {

    /**
     * 获取授权详情
     *
     * @param        $id
     * @param string $appid
     * @param string $poolid
     * @param bool   $cache
     *
     * @return array
     */
    public static function find($id, string $appid, string $poolid, $cache = true): array {
        if (empty($id)) {
            return array();
        }
        if (empty($appid)) {
            return array();
        }
        if (empty($poolid)) {
            return array();
        }

        $cacheKey = 'AuthUnion:unioninfo:appid:' . $appid . ':poolid:' . $poolid . ':id:' . $id;
        if (Cache::has($cacheKey) && $cache) {
            // $result = $this->authority->cache->get($cacheKey);
            $union = Cache::get($cacheKey);
            if (!empty($union)) {
                // return $union;
            }
        }

        $result = Curl::getInstance(true)
                      ->get(Config::get('auth.host', 'https://auth.tianfu.ink') . '/api.php/union/union_find', 'json')
                      ->appendData('id', $id)
                      ->appendData('poolid', $poolid)
                      ->appendData('appid', $appid)
                      ->appendData('cache', $cache)
                      ->toArray();

        if (!empty($result) && !empty($result['code']) && $result['code'] == 200 && !empty($result['data'])) {
            if ($cache) {
                // $this->authority->$cache->set($cacheKey, $result, Config::get('session.expire', 1440));
                // Cache::set($cacheKey, $result, Config::get('session.expire', 1440));
            }

            return $result['data'];
        }
        // $this->authority->logcat('error', 'RoleInfo::find(Data Not Found Exception)' . $cacheKey . ' ' . json_encode($result, JSON_UNESCAPED_UNICODE));
        Cache::delete($cacheKey);

        return array();
    }

    /**
     * 获取授权列表
     *
     * @param string $appid
     * @param string $poolid
     * @param bool   $cache
     *
     * @return array
     */
    public static function select(string $appid, string $poolid, $cache = true): array {
        if (empty($appid)) {
            return array();
        }

        if (empty($poolid)) {
            return array();
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
                      ->get(Config::get('auth.host', 'https://auth.tianfu.ink') . '/api.php/union/union_select', 'json')
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
        // $this->authority->logcat('error', 'union::getunionList(Data Not Found Exception)' . $cacheKey . ' ' . json_encode($result, JSON_UNESCAPED_UNICODE));
        Cache::delete($cacheKey);

        return array();
    }

    /**
     * 添加授权信息
     *
     * @param array  $union
     * @param string $openid
     * @param string $appid
     * @param string $poolid
     *
     * @return int
     */
    public static function insert(array $union, string $openid, string $appid, string $poolid): int {
        if (empty($union)) {
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
                      ->post(Config::get('auth.host', 'https://auth.tianfu.ink') . '/api.php/union/union_insert', 'json')
                      ->appendData('union', $union)
                      ->appendData('openid', $openid)
                      ->appendData('poolid', $poolid)
                      ->appendData('appid', $appid)
                      ->toArray();

        if (!empty($result) && !empty($result['code']) && $result['code'] == 200 && !empty($result['data'])) {

            return $result['data'];
        }

        // $this->authority->logcat('error', 'UnionInfo::insert(Data Not Found Exception)' . $cacheKey . ' ' . json_encode($result, JSON_UNESCAPED_UNICODE));

        return 0;
    }

    /**
     * 更新授权信息
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
                      ->post(Config::get('auth.host', 'https://auth.tianfu.ink') . '/api.php/union/union_update', 'json')
                      ->appendData('id', $id)
                      ->appendData('openid', $openid)
                      ->appendData('poolid', $poolid)
                      ->appendData('appid', $appid)
                      ->toArray();

        if (!empty($result) && !empty($result['code']) && $result['code'] == 200 && !empty($result['data'])) {

            return $result['data'];
        }

        // $this->authority->logcat('error', 'UnionInfo::update(Data Not Found Exception)' . $cacheKey . ' ' . json_encode($result, JSON_UNESCAPED_UNICODE));

        return 0;
    }

    /**
     * 删除授权信息
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
                      ->post(Config::get('auth.host', 'https://auth.tianfu.ink') . '/api.php/union/union_delete', 'json')
                      ->appendData('id', $id)
                      ->appendData('openid', $openid)
                      ->appendData('poolid', $poolid)
                      ->appendData('appid', $appid)
                      ->toArray();

        if (!empty($result) && !empty($result['code']) && $result['code'] == 200 && !empty($result['data'])) {
            return $result['data'];
        }

        // $this->authority->logcat('error', 'UnionInfo::delete(Data Not Found Exception)' . $cacheKey . ' ' . json_encode($result, JSON_UNESCAPED_UNICODE));
        return 0;
    }

}