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
    class Channel
    {

        protected $authority;

        public function __construct(Authority $authority)
        {
            $this->authority = $authority;
        }

        /**
         * @param int $appid
         * @param string $url
         * @param int $cache
         *
         * @return array|mixed
         */
        public function getChannel($appid = 0, $url = '', $cache = 1)
        {
            $cacheKey = 'AuthUnion:channel';

            if ($appid == 0) {
                $appid = Config::get('auth.appid');
            }
            $cacheKey .= ':appid:' . $appid;

            if (empty($url)) {
                $url = Request::server('document_uri');
            }
            $cacheKey .= ':domain:' . $url;

            // TODO：临时关闭缓存
            $channel = Cache::get($cacheKey);
            // $channel = $this->authority->$cache::get($cacheKey);

            if ($cache == 1 && $channel) {
                // return $channel;
            }

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

                        return array('data' => $result, 'code' => 200, 'status' => 'OK', 'msg' => '本地请求');
                    }
                } catch (DataNotFoundException $e) {
                    $this->authority->logcat('error', 'Channel::getChannel(DataNotFoundException)' . $e->getMessage());
                    $result = null;
                } catch (ModelNotFoundException $e) {
                    $this->authority->logcat('error', 'Channel::getChannel(ModelNotFoundException)' . $e->getMessage());
                    $result = null;
                } catch (DbException $e) {
                    $this->authority->logcat('error', 'Channel::getChannel(DbException)' . $e->getMessage());
                    $result = null;
                }
                self::runevent();

                return array('data' => $result, 'code' => 404, 'status' => 'Failure', 'msg' => '无效的频道信息');
            }

            $curl = Curl::getInstance()
                ->post(Config::get('auth.host') . '/api.php/ram/channel')
                ->appendData('appid', $appid)
                ->appendData('cache', $cache)
                ->appendData('url', urlencode($url));

            $json = $curl->execute();

            $code = $curl->getResponseCode();

            if ($code == 200) {
                if (!empty($json)) {
                    $result = json_decode($json, true);
                } else {
                    $result = array();
                    // self::runevent();
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

            return array();
        }

        /**
         * @param int $poolid
         * @param int $appid
         * @param string $identifier
         * @param int $cache
         *
         * @return array|mixed
         */
        public function getIdentifier($poolid = 0, $appid = 0, $identifier = '', $cache = 1)
        {
            $cacheKey = 'AuthUnion:identifier';

            if ($poolid == 0) {
                return array('data' => '', 'code' => 412, 'status' => 'Failure', 'msg' => '无效的用户池ID');
            }

            if ($appid == 0) {
                return array('data' => '', 'code' => 412, 'status' => 'Failure', 'msg' => '无效的AppId');
            }
            $cacheKey .= ':appid:' . $appid;

            if (empty($identifier)) {
                return array('data' => '', 'code' => 412, 'status' => 'Failure', 'msg' => '无效的频道标识符');
            }
            $cacheKey .= ':identifier:' . $identifier;

            // TODO：临时关闭缓存
            // $channel = Cache::get($cacheKey);
            $channel = $this->authority->$cache::get($cacheKey);
            if ($cache == 1 && $channel) {
                // return $channel;
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
                        ->cache(false)
                        ->find();

                    if (!empty($result)) {
                        if ($cache) {
                            Cache::set($cacheKey, $result, Config::get('session.expire', 1440));
                        } else {
                            Cache::delete($cacheKey);
                        }

                        return array('data' => $result, 'code' => 200, 'status' => 'OK', 'msg' => '本地请求');
                    }
                } catch (DataNotFoundException $e) {
                    $this->authority->logcat('error', 'Channel::getChannel(DataNotFoundException)' . $e->getMessage());
                    $result = array('data' => '', 'code' => 500, 'status' => 'DataNotFoundException', 'msg' => '服务异常');
                } catch (ModelNotFoundException $e) {
                    $this->authority->logcat('error', 'Channel::getChannel(ModelNotFoundException)' . $e->getMessage());
                    $result = array('data' => '', 'code' => 500, 'status' => 'ModelNotFoundException', 'msg' => '服务异常');
                } catch (DbException $e) {
                    $this->authority->logcat('error', 'Channel::getChannel(DbException)' . $e->getMessage());
                    $result = array('data' => '', 'code' => 500, 'status' => 'DbException', 'msg' => '服务异常');
                }
                self::runevent();

                return array('data' => $result, 'code' => 404, 'status' => 'Failure', 'msg' => '无效的频道信息');
            }

            $result = Curl::getInstance()
                ->post(Config::get('auth.host') . '/api.php/ram/identifier')
                ->appendData('appid', $appid)
                ->appendData('cache', $cache)
                ->appendData('identifier', $identifier)
                ->toArray();

            if (!empty($result) && $cache) {
                Cache::set($cacheKey, $result, Config::get('session.expire', 1440));
                $this->authority->$cache->set($cacheKey, $result, Config::get('session.expire', 1440));
            } else {
                Cache::delete($cacheKey);
                self::runevent();
            }

            return $result;
        }

        /**
         * 获取授权信息
         *
         * TODO：授权信息查询，存在BUG，无法隔离App
         * @param $channelid
         * @param $uuid
         * @param $roleid
         * @param int $cache
         * @return |null
         */
        public function getAccess($channelid = 0, $roleid = 404, $cache = 1)
        {
            $cacheKey = 'Channel:Access:roleid:' . $channelid . ':channelid:' . $channelid;

            try {
                $union = Db::name('union')
                    ->field(true)
                    // ->where("appid", "=", $this->appid)
                    ->where('uid', '=', !empty($uuid) ? $uuid : 404)
                    ->where('roleid', '=', !empty($roleid) ? $roleid : 404)
                    ->order('subtime desc')
                    ->cache($cache)
                    ->find();
                // 查询角色信息 * 可删除
                $role = Db::name('role')
                    ->field(true)
                    ->where('roleid', '=', !empty($roleid) ? $roleid : 404)
                    ->order('subtime desc')
                    ->cache($cache)
                    ->find();

                $access = Curl::getInstance()
                    ->post(Config::get('auth.host') . '/api.php/ram/access')
                    ->appendData('roleid', $roleid)
                    ->appendData('cache', $cache)
                    ->appendData('channelid', $channelid)
                    ->toArray();
                if (!empty($access)) {
                    // 根据当前频道查询可访问的方法
                    // @todo AppId 存在Bug
                    $access = Db::name('access')
                        ->field(true)
                        ->where('roleid', '=', !empty($roleid) ? $roleid : 404)
                        // ->where("appid", "=", $this->appid)
                        ->where('channelid', '=', $channelid)
                        ->order('subtime desc')
                        ->cache($cache)
                        ->find();
                }
                if (!empty($access)) {
                    $result = array('data' => $access, 'code' => 200, 'status' => 'ok', 'msg' => '');
                    if ($cache) {
                        Cache::set($cacheKey, $result, Config::get('session.expire', 1440));
                        $this->authority->$cache->set($cacheKey, $result, Config::get('session.expire', 1440));
                    } else {
                        Cache::delete($cacheKey);
                    }
                } else {
                    $result = array('data' => $access, 'code' => 404, 'status' => 'Failure', 'msg' => '无效的授权信息');
                }
            } catch (DataNotFoundException $e) {
                $this->authority->logcat('error', 'Authority::Check(DataNotFoundException ' . __LINE__ . ')' . $e->getMessage());

                $result = array('data' => '', 'code' => 500, 'status' => 'DataNotFoundException', 'msg' => '服务异常');
            } catch (ModelNotFoundException $e) {
                $this->authority->logcat('error', 'Authority::Check(ModelNotFoundException ' . __LINE__ . ')' . $e->getMessage());

                $result = array('data' => '', 'code' => 500, 'status' => 'ModelNotFoundException', 'msg' => '服务异常');
            } catch (DbException $e) {
                $this->authority->logcat('error', 'Authority::Check(DbException ' . __LINE__ . ')' . $e->getMessage());

                $result = array('data' => '', 'code' => 500, 'status' => 'DbException', 'msg' => '服务异常');
            }

            return $result;
        }

        /**
         * TODO：发送消息通知的方式无法共用，并不是每个系统都有这个方法
         * TODO：可以用发送post消息的方式，将消息发送到消息中心
         *
         */
        public function runevent()
        {
            $this->taobao();
        }

        private function taobao()
        {
            try {
                $ip = Os::getIpvs();
                $curl = Curl::getInstance()
                    ->get('http://ip.taobao.com/service/getIpInfo.php?ip=' . $ip, 'json');
                $result = $curl->toArray();

                $os = Os::getInfo();
                $remark = $os['os'] . " " . $os['brand'] . " " . $os['model'] . " " . implode("_", $os["browser"]) . " " . $os['ipvs'] . " ";

                if (!empty($result)) {
                    if ($result['code'] == 0) {
                        $remark .= implode('_', $result['data']) . " " . $ip;
                    } else {
                        $this->authority->logcat('error', 'IP Info Warning ' . json_encode($result, JSON_UNESCAPED_UNICODE));

                        return $this->juhe();
                    }
                } else {
                    $this->authority->logcat('error', 'IP Info Error');

                    return $this->juhe();
                }

                $user = Db::name('user')
                    ->withoutField('password')
                    ->where('uid', '=', 12)
                    ->find();
                Notice::runevent(
                    $user['wxid'],
                    Session::get('nickname', '匿名用户'),
                    '无效频道TB',
                    Request::url(true),
                    Request::url(true),
                    Request::time(),
                    '频道测试',
                    $remark
                );

                $this->authority->logcat('error', 'Auth::Channel（运行预警：无效频道）' . json_encode(Request::server(), JSON_UNESCAPED_UNICODE));
            } catch (DataNotFoundException $e) {
                $this->authority->logcat('error', "Channel::Runevent(DataNotFoundException)" . $e->getMessage());
            } catch (ModelNotFoundException $e) {
                $this->authority->logcat('error', "Channel::Runevent(ModelNotFoundException)" . $e->getMessage());
            } catch (DbException $e) {
                $this->authority->logcat('error', "Channel::Runevent(DbException)" . $e->getMessage());
            }

            return false;
        }

        private function juhe()
        {
            try {
                $ip = Os::getIpvs();
                $curl = Curl::getInstance()
                    ->get("http://apis.juhe.cn/ip/ipNew?ip=" . $ip . "&key=f242a7b62e202745e0964a877f3657de", 'json');
                $result = $curl->toArray();

                $os = Os::getInfo();
                $remark = $os['os'] . " " . $os['brand'] . " " . $os['model'] . " " . implode("_", $os["browser"]) . " " . $os['ipvs'] . " ";

                if (!empty($result)) {
                    if ($result['resultcode'] == 200) {
                        $remark .= implode('_', $result['result']) . " " . $ip;
                    } else {
                        $this->authority->logcat('error', 'IP Info Warning ' . json_encode($result, JSON_UNESCAPED_UNICODE));
                    }
                } else {
                    $this->authority->logcat('error', 'IP Info Error ');
                }

                $user = Db::name('user')
                    ->withoutField('password')
                    ->where('uid', '=', 12)
                    ->find();

                $this->authority->logcat(
                    'error', 'Channel::Runevent（Channel：运行预警：无效频道）' . json_encode(Request::server(), JSON_UNESCAPED_UNICODE)
                );

                return Notice::runevent(
                    $user['wxid'],
                    Session::get('nickname', '匿名用户'),
                    '无效频道 Juhe',
                    Request::url(true),
                    Request::url(true),
                    Request::time(),
                    '频道测试',
                    $remark
                );
            } catch (DataNotFoundException $e) {
                $this->authority->logcat('error', "Channel::Runevent(DataNotFoundException)" . $e->getMessage());
            } catch (ModelNotFoundException $e) {
                $this->authority->logcat('error', "Channel::Runevent(ModelNotFoundException)" . $e->getMessage());
            } catch (DbException $e) {
                $this->authority->logcat('error', "Channel::Runevent(DbException)" . $e->getMessage());
            }

            return false;
        }

    }