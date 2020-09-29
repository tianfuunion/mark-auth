<?php

declare (strict_types=1);

namespace mark\auth\entity;

use think\facade\Config;
use think\facade\Cache;
use mark\http\Curl;
use mark\auth\Authorize;
use mark\response\Responsive;

final class AppInfo {

    public static $type = array(
        array('id' => 0, 'title' => '网页 App', 'name' => 'WebApp'),
        array('id' => 1, 'title' => '本地 App', 'name' => 'NativeApp'),
        array('id' => 2, 'title' => '混合 App', 'name' => 'HybridApp'),
        array('id' => 3, 'title' => 'IOS App', 'name' => 'IosApp'),
        array('id' => 4, 'title' => 'Android App', 'name' => 'AndroidApp'),
    );

    public static function getAppInfo(string $openid, string $appid, string $poolid, $cache = true): array {
        if (empty($openid)) {
            return Responsive::display('', 412, '', '无效的授权ID', 'origin');
        }
        if (empty($appid)) {
            return Responsive::display('', 412, '', '无效的AppID', 'origin');
        }
        if (empty($poolid)) {
            return Responsive::display('', 412, '', '无效的PoolID', 'origin');
        }

        $cacheKey = 'AuthUnion:appinfo:poolid:' . $poolid . ':appid:' . $appid;

        if (Cache::has($cacheKey) && $cache) {
            // $result = $this->authority->cache->get($cacheKey);
            $app = Cache::get($cacheKey);
            if (!empty($app)) {
                // return $app;
            }
        }

        $result = Curl::getInstance(true)
                      ->get(Config::get('auth.host', Authorize::$host) . '/api.php/app/app_info', 'json')
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
        // $this->authority->logcat('error', 'RoleInfo::getRoleInfo(Data Not Found Exception)' . $cacheKey . ' ' . json_encode($result, JSON_UNESCAPED_UNICODE));
        Cache::delete($cacheKey);

        return $result;
    }

}