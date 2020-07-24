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

use mark\wechat\notice\Notice;
use mark\http\Curl;
use mark\system\Os;
use mark\auth\middleware\Authority;

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
     * @param int    $appid
     * @param string $url
     * @param int    $cache
     *
     * @return array|mixed
     */
    public function getChannel($appid = 0, $url = '', $cache = 1) {
        $cacheKey = 'AuthUnion:channel';
        $result = array();
        if ($appid == 0) {
            $appid = Config::get('auth.appid');
        }
        $cacheKey .= ':appid:' . $appid;

        if (empty($url)) {
            $url = Request::server('document_uri');
        }
        $cacheKey .= ':domain:' . $url;

        // TODO：临时关闭缓存
        // $channel = Cache::get($cacheKey);
        // $channel = $this->authority->cache->get($cacheKey);
        // if ($cache == 1 && !empty($channel)) {
        // return $channel;
        // }

        if (Config::get('auth.level', 'slave') == 'master') {
            try {
                $result = Db::name('app_channel')
                            ->table('pro_app app, pro_app_channel channel')
                            ->field('channel.*, app.appid, app.domain, app.host')
                            ->where('app.appid = channel.appid')
                            ->where('app.appid', '=', $appid)
                    // ->where("app.domain", "=", $this->request->rootdomain())
                            ->where('channel.url', '=', $url)
                            ->order('channel.displayorder asc')
                            ->cache(false)
                            ->find();

                if (!empty($result)) {
                    if ($cache) {
                        Cache::set($cacheKey, $result, Config::get('session.expire', 1440));
                    } else {
                        Cache::delete($cacheKey);
                    }

                    return $result;
                }
            } catch (DataNotFoundException $e) {
                $this->authority->logcat('error', 'Channel::getChannel(DataNotFoundException)' . $e->getMessage());
            } catch (ModelNotFoundException $e) {
                $this->authority->logcat('error', 'Channel::getChannel(ModelNotFoundException)' . $e->getMessage());
            } catch (DbException $e) {
                $this->authority->logcat('error', 'Channel::getChannel(DbException)' . $e->getMessage());
            }
            self::runevent();

            return $result;
        }

        $curl = Curl::getInstance()
                    ->get(Config::get('auth.host') . '/api.php/ram/channel')
                    ->appendData('appid', $appid)
                    ->appendData('cache', $cache)
                    ->appendData('url', urlencode($url));

        $json = $curl->execute();

        $code = $curl->getResponseCode();

        if ($code == 200) {
            if (!empty($json)) {
                $result = json_decode($json, true);
            }

            if (!empty($result) && $cache) {
                Cache::set($cacheKey, $result, Config::get('session.expire', 1440));
            } else {
                Cache::delete($cacheKey);
            }

            return $result;
        }
        self::runevent();
        $this->authority->logcat('error', 'Channel:getChannel(' . $code . ')' . json_encode($curl->getInfo(), JSON_UNESCAPED_UNICODE));

        return $result;
    }

    /**
     * 根据标识符获取频道信息
     *
     * @param int    $poolid
     * @param int    $appid
     * @param string $identifier
     * @param int    $cache
     *
     * @return array|mixed|\think\Model|null
     */
    public function getIdentifier($poolid, $appid, $identifier = '', $cache = 1) {
        $cacheKey = 'AuthUnion:identifier';
        $result = array();

        if (empty($poolid)) {
            $this->authority->logcat('error', 'Channel::getIdentifier(无效的用户池ID)');

            return $result;
        }
        $cacheKey .= ':poolid:' . $poolid;
        if (empty($appid)) {
            $this->authority->logcat('error', 'Channel::getIdentifier(无效的AppId)');

            return $result;
        }
        $cacheKey .= ':appid:' . $appid;

        if (empty($identifier)) {
            $this->authority->logcat('error', 'Channel::getIdentifier(无效的频道标识符)');

            return $result;
        }

        $cacheKey .= ':identifier:' . $identifier;
        if (Cache::has($cacheKey)) {
            // TODO：临时关闭缓存
            $result = $this->authority->cache->get($cacheKey);
            // return Cache::get($cacheKey);
        }

        if (Config::get('auth.level', 'slave') == 'master') {
            try {
                $result = Db::name('app_channel')
                            ->table('pro_app app, pro_app_channel channel')
                            ->field('channel.*, app.appid, app.domain, app.host')
                            ->where('app.appid = channel.appid')
                            ->where('app.poolid', '=', $poolid)
                            ->where('app.appid', '=', $appid)
                            ->where('channel.identifier', '=', $identifier)
                            ->order('channel.displayorder asc')
                            ->cache($cache)
                            ->find();

                if (!empty($result)) {
                    if ($cache == 1) {
                        // Cache::set($cacheKey, $result, Config::get('session.expire', 1440));
                    } else {
                        // Cache::delete($cacheKey);
                    }

                    return $result;
                }
            } catch (DataNotFoundException $e) {
                $this->authority->logcat('error', 'Channel::getIdentifier(DataNotFoundException)' . $e->getMessage());
            } catch (ModelNotFoundException $e) {
                $this->authority->logcat('error', 'Channel::getIdentifier(ModelNotFoundException)' . $e->getMessage());
            } catch (DbException $e) {
                $this->authority->logcat('error', 'Channel::getIdentifier(DbException)' . $e->getMessage());
            }
            self::runevent();
        }

        $channel = Curl::getInstance()
                       ->get(Config::get('auth.host') . '/api.php/ram/identifier')
                       ->appendData('poolid', $poolid)
                       ->appendData('appid', $appid)
                       ->appendData('cache', $cache)
                       ->appendData('identifier', $identifier)
                       ->toArray();

        if (!empty($channel)) {
            if (is_string($channel)) {
                $channel = json_decode($channel, true);
            }

            if (!empty($channel) && $channel['code'] == 200) {
                $result = $channel['data'];
            }
        } else {
            $this->authority->logcat('error', 'Channel::getIdentifier()' . json_encode($channel, JSON_UNESCAPED_UNICODE));
        }

        if (!empty($result) && $cache) {
            // Cache::set($cacheKey, $result, Config::get('session.expire', 1440));
            // $this->authority->$cache->set($cacheKey, $result, Config::get('session.expire', 1440));
        } else {
            // Cache::delete($cacheKey);
            self::runevent();
        }

        return $result;
    }

    /**
     * 根据标识符，获取授权信息
     *
     * TODO：授权信息查询，存在BUG，无法隔离App
     *
     * @param        $channelid
     * @param string $identifier
     * @param        $appid
     * @param        $poolid
     * @param int    $roleid
     *
     * @return array|mixed
     */
    public function getAccess($channelid, string $identifier, $appid, $poolid, $roleid = 404) {
        $cacheKey = 'channel:access:channelid:' . $channelid . ':appid:' . $appid . ':poolid:' . $poolid . ':roleid:' . $channelid;

        if (Cache::has($cacheKey)) {
            return Cache::get($cacheKey);
        }

        $access = Curl::getInstance()
                      ->get(Config::get('auth.host') . '/api.php/ram/access')
                      ->appendData('identifier', $identifier)
                      ->appendData('channelid', $channelid)
                      ->appendData('appid', $appid)
                      ->appendData('poolid', $poolid)
                      ->appendData('roleid', $roleid)
                      ->toArray();

        if (!empty($access) && !empty($access['code']) && $access['code'] == 200 && !empty($access['data'])) {
            Cache::set($cacheKey, $access['data'], Config::get('session.expire', 1440));

            // $this->authority->$cache->set($cacheKey, $access, Config::get('session.expire', 1440));
            return $access['data'];
        } else {
            $this->authority->logcat('error', 'Channel::getAccess(DataNotFoundException)' . $cacheKey);

            Cache::delete($cacheKey);
        }

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
            $result = Curl::getInstance()
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
            $result = Curl::getInstance()
                          ->get("http://apis.juhe.cn/ip/ipNew?ip=" . $ip . "&key=f242a7b62e202745e0964a877f3657de", 'json')
                          ->toArray();

            // $remark = Os::getOs() . " " . Os::getBrand()['brand'] . " " . Os::getBrand()['model'] . " " . implode("_", Os::getBrowser()) . " " . $ip . " ";
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