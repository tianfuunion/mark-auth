<?php

declare (strict_types=1);

namespace mark\auth\model;

use think\facade\Cache;
use think\facade\Config;
use think\facade\Db;
use think\facade\Session;
use think\facade\Request;

use think\db\exception\DataNotFoundException;
use think\db\exception\ModelNotFoundException;
use think\db\exception\DbException;

use mark\auth\middleware\Authority;
use mark\http\Curl;
use mark\system\Os;
use mark\wechat\notice\Notice;

/**
 * Class Channel
 *
 * @package mark\auth\model
 */
class Channel {

    protected $authority;

    public function __construct(Authority $authority) {
        $this->authority = $authority;
    }

    /**
     * 获取频道信息
     *
     * @param int    $appid
     * @param string $url
     * @param bool   $cache
     *
     * @return array|bool|false|string|\think\Model
     * @throws \think\db\exception\DataNotFoundException
     * @throws \think\db\exception\DbException
     * @throws \think\db\exception\ModelNotFoundException
     * @deprecated
     */
    public static function getChannel($appid = 0, $url = '', $cache = true) {
        $cacheKey = 'AuthUnion:channel:appid:' . $appid;

        if (empty($url)) {
            $url = Request::server('document_uri');
        }
        $cacheKey .= ':domain:' . $url;

        // TODO：临时关闭缓存
        if (Cache::has($cacheKey) && $cache) {
            // $channel = $this->authority->cache->get($cacheKey);
            $channel = Cache::get($cacheKey);
            if (!empty($channel)) {
                // return $channel;
            }
        }

        if (Config::get('auth.level', 'slave') == 'master') {
            $channel = Db::name('app_channel')
                         ->table('pro_app app, pro_app_channel channel')
                         ->field('channel.*, app.appid, app.domain, app.host')
                         ->where('app.appid = channel.appid')
                         ->where('app.appid', '=', $appid)
                // ->where("app.domain", "=", $this->request->rootdomain())
                         ->where('channel.url', '=', $url)
                         ->order('channel.displayorder')
                // ->cache($this->authority->expire)
                         ->find();

            if (!empty($channel)) {
                if ($cache) {
                    Cache::set($cacheKey, $channel, Config::get('session.expire', 1440));
                } else {
                    Cache::delete($cacheKey);
                }

                return $channel;
            }

            self::runevent();

            return array();
        }

        $result = Curl::getInstance(true)
                      ->get(Config::get('auth.host', 'https://auth.tianfu.ink') . '/api.php/ram/channel', 'json')
                      ->appendData('appid', $appid)
                      ->appendData('cache', $cache)
                      ->appendData('url', urlencode($url))
                      ->toArray();

        if (!empty($result)) {
            if ($cache) {
                Cache::set($cacheKey, $result, Config::get('session.expire', 1440));
            } else {
                Cache::delete($cacheKey);
            }

            return $result;
        }
        Cache::delete($cacheKey);
        self::runevent();

        // $this->authority->logcat('error', 'Channel:getChannel(DataNotFoundException)' . $cacheKey . ' ' . json_encode($result, JSON_UNESCAPED_UNICODE));

        return array();
    }

    /**
     * 根据标识符获取频道信息
     *
     * @param string $appid
     * @param string $poolid
     * @param string $identifier
     * @param bool   $cache
     *
     * @return array|mixed|\think\Model
     * @throws \think\db\exception\DataNotFoundException
     * @throws \think\db\exception\DbException
     * @throws \think\db\exception\ModelNotFoundException
     */
    public static function getIdentifier(string $appid, string $poolid, string $identifier, $cache = true) {
        $cacheKey = 'AuthUnion:identifier:appid:' . $appid . ':poolid:' . $poolid . ':identifier:' . $identifier;
        // TODO：临时关闭缓存
        if (Cache::has($cacheKey) && $cache) {
            // $result = $this->authority->cache->get($cacheKey);
            $channel = Cache::get($cacheKey);
            if (!empty($channel)) {
                // return $channel;
            }
        }

        if (Config::get('auth.level', 'slave') == 'master') {
            $channel = Db::name('app_channel')
                         ->field(true)
                         ->where('poolid', '=', $poolid)
                         ->where('appid', '=', $appid)
                         ->where('identifier', '=', $identifier)
                         ->order('displayorder')
                // ->cache($this->authority->expire)
                         ->find();

            if (!empty($channel)) {
                if ($cache) {
                    // Cache::set($cacheKey, $channel, Config::get('session.expire', 1440));
                } else {
                    // Cache::delete($cacheKey);
                }

                return $channel;
            }

            self::runevent();

            return array();
        }

        $result = Curl::getInstance(true)
                      ->get(Config::get('auth.host', 'https://auth.tianfu.ink') . '/api.php/ram/identifier', 'json')
                      ->appendData('poolid', $poolid)
                      ->appendData('appid', $appid)
                      ->appendData('identifier', urlencode($identifier))
                      ->appendData('cache', $cache)
                      ->toArray();

        if (!empty($result) && !empty($result['code']) && $result['code'] == 200 && !empty($result['data'])) {
            if ($cache) {
                // $this->authority->$cache->set($cacheKey, $result, Config::get('session.expire', 1440));
                // Cache::set($cacheKey, $result, Config::get('session.expire', 1440));
            }

            return $result['data'];
        }
        // $this->authority->logcat('error', 'Channel::getIdentifier(Channel is null)' . json_encode($result, JSON_UNESCAPED_UNICODE));

        Cache::delete($cacheKey);
        self::runevent();

        return array();
    }

    /**
     * 根据标识符，获取权限信息
     *
     * @param string $appid
     * @param string $poolid
     * @param int    $channelid
     * @param int    $roleid
     * @param bool   $cache
     *
     * @return array|mixed|\think\Model
     * @throws \think\db\exception\DataNotFoundException
     * @throws \think\db\exception\DbException
     * @throws \think\db\exception\ModelNotFoundException
     */
    public static function getAccess(string $appid, string $poolid, int $channelid, $roleid = 404, $cache = true) {
        if (empty($appid)) {
            $appid = Request::param('appid', Config::get("auth.appid"));
        }

        if (empty($poolid)) {
            $poolid = Request::param('poolid', Config::get("auth.poolid"));
        }

        if (empty($channelid)) {
            return array();
        }
        $cacheKey = 'channel:access:appid:' . $appid . ':poolid:' . $poolid . ':channelid:' . $channelid . ':roleid:' . $roleid;

        if (Cache::has($cacheKey) && $cache) {
            $access = Cache::get($cacheKey);
            if (!empty($access)) {
                // return $access;
            }
        }

        if (Config::get('auth.level', 'slave') == 'master') {
            $access = Db::name('access')
                        ->field(true)
                        ->where('appid', '=', $appid)
                        ->where('poolid', '=', $poolid)
                        ->where('channelid', '=', $channelid)
                        ->where('roleid', '=', $roleid)
                        ->order('subtime', 'desc')
                // ->cache($this->authority->expire)
                        ->find();

            if (!empty($access)) {
                // Cache::set($cacheKey, $result, Config::get('session.expire', 1440));
                return $access;
            }
            // $this->authority->logcat('error', 'Channel::getAccess(Data Not Found Exception)');
            // Cache::delete($cacheKey);

            return array();
        }

        $result = Curl::getInstance(true)
                      ->get(Config::get('auth.host', 'https://auth.tianfu.ink') . '/api.php/ram/access', 'json')
                      ->appendData('appid', $appid)
                      ->appendData('poolid', $poolid)
                      ->appendData('channelid', $channelid)
                      ->appendData('roleid', $roleid)
                      ->appendData('cache', $cache ? 1 : 0)
                      ->toArray();

        if (!empty($result) && !empty($result['code']) && $result['code'] == 200 && !empty($result['data'])) {
            if ($cache) {
                // $this->authority->$cache->set($cacheKey, $result, Config::get('session.expire', 1440));
                Cache::set($cacheKey, $result['data'], Config::get('session.expire', 1440));
            }

            return $result['data'];
        }
        // $this->authority->logcat('error', 'Channel::getAccess(Data Not Found Exception)' . $cacheKey . ' ' . json_encode($result, JSON_UNESCAPED_UNICODE));
        Cache::delete($cacheKey);

        return array();
    }

    /**
     * 获取桌面频道列表
     *
     * @param string $appid
     * @param string $poolid
     * @param int    $roleid
     * @param bool   $cache
     *
     * @return array|mixed
     */
    public static function getWorkspace(string $appid, string $poolid, $roleid = 404, $cache = true) {
        $cacheKey = 'channel:workspace:appid:' . $appid . ':poolid:' . $poolid . ':roleid:' . $roleid;

        if (Cache::has($cacheKey) && $cache) {
            $workspace = Cache::get($cacheKey);
            if (!empty($workspace)) {
                // return $workspace;
            }
        }

        $result = Curl::getInstance(true)
                      ->get(Config::get('auth.host', 'https://auth.tianfu.ink') . '/api.php/ram/workspace', 'json')
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

            return $result['data'] ?? array();
        }

        // $this->authority->logcat('error', 'Channel::getWorkspace(Data Not Found Exception)' . $cacheKey . ' ' . json_encode($result, JSON_UNESCAPED_UNICODE));

        Cache::delete($cacheKey);

        return array();
    }

    /**
     * TODO：发送消息通知的方式无法共用，并不是每个系统都有这个方法
     * TODO：可以用发送post消息的方式，将消息发送到消息中心
     *
     */
    public function runevent() {
        $this->taobao();
    }

    /**
     * 淘宝IP
     *
     * @return bool|mixed|string
     */
    private function taobao() {
        try {
            $ip = Os::getIpvs();
            $result = Curl::getInstance(true)
                          ->get('http://ip.taobao.com/service/getIpInfo.php?ip=' . $ip, 'json')
                          ->toArray();

            $remark = Os::getOs('string') . " " . Os::getBrand('string') . Os::getBrowser('string') . " " . $ip . " ";

            if (!empty($result)) {
                if ($result['code'] == 0) {
                    $remark .= implode('_', $result['data']) . " " . $ip;
                } else {
                    $this->authority->logcat('error', 'TaoBao IP Info Warning ' . json_encode($result, JSON_UNESCAPED_UNICODE));

                    return $this->juhe();
                }
            } else {
                $this->authority->logcat('error', 'TaoBao IP Info Error');

                return $this->juhe();
            }

            $user = Db::name('user')
                      ->withoutField('password')
                      ->where('uid', '=', 12)
                      ->find();
            Notice::runevent(
                $user['wxid'],
                Session::get('nickname', '匿名用户'),
                '无效频道 淘宝',
                Request::url(true),
                Request::url(true),
                Request::time(),
                '频道测试',
                $remark
            );

            $this->authority->logcat('error', 'Channel::taobao（运行预警：无效频道）' . json_encode(Request::server(), JSON_UNESCAPED_UNICODE));
        } catch (DataNotFoundException $e) {
            $this->authority->logcat('error', "Channel::taobao(DataNotFoundException)" . $e->getMessage());
        } catch (ModelNotFoundException $e) {
            $this->authority->logcat('error', "Channel::taobao(ModelNotFoundException)" . $e->getMessage());
        } catch (DbException $e) {
            $this->authority->logcat('error', "Channel::taobao(DbException)" . $e->getMessage());
        }

        return false;
    }

    /**
     * 聚合IP
     *
     * @return bool|mixed|string
     */
    private function juhe() {
        try {
            $ip = Os::getIpvs();
            $result = Curl::getInstance(true)
                          ->get("http://apis.juhe.cn/ip/ipNew?ip=" . $ip . "&key=f242a7b62e202745e0964a877f3657de", 'json')
                          ->toArray();
            $remark = Os::getOs('string') . " " . Os::getBrand('string') . Os::getBrowser('string') . " " . $ip . " ";
            if (!empty($result)) {
                if ($result['resultcode'] == 200) {
                    $remark .= implode('_', $result['result']) . " " . $ip;
                } else {
                    $this->authority->logcat('error', 'juhe IP Info Warning ' . json_encode($result, JSON_UNESCAPED_UNICODE));
                }
            } else {
                $this->authority->logcat('error', 'juhe IP Info Error');
            }

            $user = Db::name('user')
                      ->withoutField('password')
                      ->where('uid', '=', 12)
                      ->find();

            $this->authority->logcat('error', 'Channel::Runevent（Channel：运行预警：无效频道）' . json_encode(Request::server(), JSON_UNESCAPED_UNICODE));

            return Notice::runevent(
                $user['wxid'],
                Session::get('nickname', '匿名用户'),
                '无效频道 聚合',
                Request::url(true),
                Request::url(true),
                Request::time(),
                '频道测试',
                $remark
            );
        } catch (DataNotFoundException $e) {
            $this->authority->logcat('error', "Channel::juhe(DataNotFoundException)" . $e->getMessage());
        } catch (ModelNotFoundException $e) {
            $this->authority->logcat('error', "Channel::juhe(ModelNotFoundException)" . $e->getMessage());
        } catch (DbException $e) {
            $this->authority->logcat('error', "Channel::juhe(DbException)" . $e->getMessage());
        }

        return false;
    }

}