<?php

declare (strict_types=1);

namespace mark\auth\entity;

use think\facade\Cache;
use think\facade\Config;

use mark\http\Curl;

final class Organize {

    /**
     * 获取组织详情
     *
     * @param string $openid
     * @param        $orgid
     * @param bool   $cache
     *
     * @return array
     */
    public static function getOrganizeInfo(string $openid, $orgid, $cache = true): array {
        if (empty($orgid)) {
            return array();
        }
        if (empty($openid)) {
            return array();
        }

        $cacheKey = 'AuthUnion:organize:info:orgid:' . $orgid;
        if (Cache::has($cacheKey) && $cache) {
            // $organize = $this->authority->cache->get($cacheKey);
            $organize = Cache::get($cacheKey);
            if (!empty($organize)) {
                // return $organize;
            }
        }

        $result = Curl::getInstance(true)
                      ->get(Config::get('auth.host', 'https://auth.tianfu.ink') . '/api.php/organize/organize_info', 'json')
                      ->appendData('orgid', $orgid)
                      ->appendData('openid', $openid)
                      ->appendData('cache', $cache)
                      ->toArray();

        if (!empty($result) && !empty($result['code']) && $result['code'] == 200 && !empty($result['data'])) {
            if ($cache) {
                // $this->authority->$cache->set($cacheKey, $result, Config::get('session.expire', 1440));
                // Cache::set($cacheKey, $result, Config::get('session.expire', 1440));
            }
        }

        return $result;
    }

    /**
     * 列表组织架构
     *
     * @param string $openid
     * @param bool   $cache
     *
     * @return array
     */
    public static function getOrganizeList(string $openid, string $orgid, $cache = true): array {
        if (empty($openid)) {
            return array();
        }
        if (empty($orgid)) {
            return array();
        }

        $cacheKey = 'AuthUnion:organize:listview:orgid:' . $orgid;
        if (Cache::has($cacheKey) && $cache) {
            // $result = $this->authority->cache->get($cacheKey);
            $organizes = Cache::get($cacheKey);
            if (!empty($organizes)) {
                // TODO：临时关闭缓存
                // return $organizes;
            }
        }

        $result = Curl::getInstance(true)
                      ->get(Config::get('auth.host', 'https://auth.tianfu.ink') . '/api.php/organize/organize_list', 'json')
                      ->appendData('openid', $openid)
                      ->appendData('orgid', $orgid)
                      ->appendData('cache', $cache)
                      ->toArray();

        return $result;
    }

    /**
     * 树形组织架构
     *
     * @param string $openid
     * @param string $orgid
     * @param bool   $cache
     *
     * @return array
     */
    public static function getOrganizeTree(string $openid, string $orgid, $cache = true): array {
        if (empty($openid)) {
            return array();
        }
        if (empty($orgid)) {
            return array();
        }

        $cacheKey = 'AuthUnion:organize:treeview:orgid:' . $orgid;
        if (Cache::has($cacheKey) && $cache) {
            // $result = $this->authority->cache->get($cacheKey);
            $organizes = Cache::get($cacheKey);
            if (!empty($organizes)) {
                // TODO：临时关闭缓存
                // return $organizes;
            }
        }

        $result = Curl::getInstance(true)
                      ->get(Config::get('auth.host', 'https://auth.tianfu.ink') . '/api.php/organize/organize_tree', 'json')
                      ->appendData('openid', $openid)
                      ->appendData('orgid', $orgid)
                      ->appendData('cache', $cache)
                      ->toArray();
        if (!empty($result)) {
            return $result;
        }

        return array();
    }

    /**
     * 添加角色信息
     *
     * @param string $openid
     * @param array  $organize
     *
     * @return array
     */
    public static function createOrganize(string $openid, array $organize): array {
        if (empty($openid)) {
            return array('data' => '', 'code' => 401, 'status' => '', 'msg' => '无效的OpenID');
        }
        if (empty($organize)) {
            return array('data' => '', 'code' => 412, 'status' => '', 'msg' => '请输入组织名称');
        }

        $result = Curl::getInstance(true)
                      ->post(Config::get('auth.host', 'https://auth.tianfu.ink') . '/api.php/organize/organize_create', 'json')
                      ->appendData('openid', $openid)
                      ->appendData('organize', $organize)
                      ->toArray();

        return $result;
    }

    /**
     * 更新角色信息
     *
     * /**
     * @param string $openid
     * @param        $orgid
     * @param array  $organize
     *
     * @return array
     */
    public static function updateOrganize(string $openid, $orgid, array $organize): array {
        if (empty($orgid)) {
            return array('data' => '', 'code' => 412, 'status' => '', 'msg' => '无效的组织ID');
        }
        if (empty($organize)) {
            return array('data' => '', 'code' => 412, 'status' => '', 'msg' => '无效的组织名称');
        }
        if (empty($openid)) {
            return array('data' => '', 'code' => 401, 'status' => '', 'msg' => '无效的OpenID');
        }

        $result = Curl::getInstance(true)
                      ->post(Config::get('auth.host', 'https://auth.tianfu.ink') . '/api.php/organize/organize_update', 'json')
                      ->appendData('openid', $openid)
                      ->appendData('orgid', $orgid)
                      ->appendData('organize', $organize)
                      ->toArray();

        return $result;
    }

    /**
     * 删除组织节点
     *
     * @note 如果该节点存在子节点，则无法删除
     *
     * @param string $openid
     * @param        $orgid
     *
     * @return array
     */
    public static function deleteOrganize(string $openid, $orgid): array {
        if (empty($orgid)) {
            return array('data' => '', 'code' => 412, 'status' => '', 'msg' => '无效的组织ID');
        }

        if (empty($openid)) {
            return array('data' => '', 'code' => 401, 'status' => '', 'msg' => '无效的OpenID');
        }

        $result = Curl::getInstance(true)
                      ->post(Config::get('auth.host', 'https://auth.tianfu.ink') . '/api.php/organize/organize_delete', 'json')
                      ->appendData('openid', $openid)
                      ->appendData('orgid', $orgid)
                      ->toArray();

        return $result;
    }

}
