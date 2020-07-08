<?php

    declare (strict_types=1);

    namespace mark\auth\middleware;

    use think\facade\Config;

    use mark\auth\AuthUnion;
    use mark\auth\Authorize;
    use mark\auth\entity\AuthInfo;
    use mark\auth\model\Channel;

    use mark\request\Request;

    use mark\system\Os;
    use Psr\SimpleCache\CacheInterface;

    /**
     * Class Authority
     * @package mark\auth\middleware
     */
    abstract class Authority
    {

        protected $appid = '';
        protected $poolid = '';
        protected $debug = false;
        protected $cache = false;

        protected $expire = 1440;

        protected $channel;

        public function __construct()
        {
            $this->logcat('info', 'Authority::construct(' . Os::getAgent() . ')');
            $this->channel = new Channel($this);
        }

        final function setAppId($appid): void
        {
            $this->appid = $appid;
        }

        final function setPoolId($poolid): void
        {
            $this->poolid = $poolid;
        }

        final function setDebug($debug): void
        {
            $this->debug = $debug;
        }

        final function setCache(CacheInterface $cache): void
        {
            $this->cache = $cache;
        }

        final function setExpire($expire): void
        {
            $this->expire = $expire;
        }

        private $before_handle;

        final protected function before_handle(callable $callback): void
        {
            $this->before_handle = $callback;
        }

        private $after_handle;

        final protected function after_handle(callable $callback): void
        {
            $this->after_handle = $callback;
        }

        /**
         * 处理器
         *
         * @return \think\response\Redirect
         */
        protected function handler()
        {
            if (!empty($this->before_handle)) {
                call_user_func_array($this->before_handle, array());
            }

            // 初始化
            $this->initialize();

            /**
             * TODO：1、排除验证码,随后数据来源可从数据库中获取
             */
            if (stripos(Request::server('request_uri'), 'captcha') != false || Request::server('request_uri') == '/') {
                $this->logcat('info', '排除验证码：' . $this->getIdentifier());
                return $this->response('', 200);
            }

            $ignore = $this->internalIgnore();
            if (!empty($ignore) && is_array($ignore)) {
                foreach ($ignore as $key => $item) {
                    if (stripos(rtrim(Request::server('request_uri'), "/"), $item)) {
                        $this->logcat('info', '自定义排除项：' . $this->getIdentifier());
                        return $this->response('', 200);
                    }
                }
            }

            // $result = $this->channel->getChannel($this->appid, rtrim(Request::server('document_uri'), "/"), $this->cache);
            $result = $this->channel->getIdentifier($this->poolid, $this->appid, $this->getIdentifier(), $this->cache);

            $this->logcat('error', 'Result:' . json_encode($result, JSON_UNESCAPED_UNICODE));

            if (!empty($result)) {
                if (is_string($result)) {
                    $result = json_decode($result, true);
                }
                switch ($result['code']) {
                    case 200:
                        $channel = $result['data'];
                        break;
                    default:
                        return $this->response($result['data'], $result['code'], $result['status'], $result['msg']);
                        break;
                }
            } else {
                $this->logcat('error', 'Result:' . json_encode($result, JSON_UNESCAPED_UNICODE));

                return $this->response('', 503);
            }

            if (Authorize::isAdmin()) {
                $this->logcat('debug', 'Authority::Check(Super Manager has Channel privileges)');
            } elseif (!empty($channel)) {
                if ($channel['status'] != 1) {
                    $this->logcat('error', 'Authority::checkChannel(501 ' . __LINE__ . ') Channel information not available ' . json_encode($channel, JSON_UNESCAPED_UNICODE));

                    return $this->response('', 503, 'Channel information not available', '该频道尚未启用');
                }
            } else {
                $this->logcat('error', 'Authority::checkChannel(412 ' . __LINE__ . ') Invalid Channel information' . json_encode($channel, JSON_UNESCAPED_UNICODE));

                return $this->response('', 412, 'Invalid Channel information ', '无效的频道信息');
            }

            // 不为公开则必检查* 检查频道是否需要权限检查
            if ($channel[AuthInfo::$modifier] == AuthInfo::$public) {
                // 该页面为公开页面，无需检查
                $this->logcat('info', '该页面为公开页面，无需检查：' . $this->getIdentifier());
                return $this->response('', 200);
            }

            // 更新用户登录有效期
            if (!Authorize::isLogin()) {
                if (Request::isAjax() || Request::isPjax()) {
                    $this->logcat('error', 'Authority::checkChannel(401 ' . __LINE__ . ') Ajax Unauthorized Channel() ' . json_encode($channel, JSON_UNESCAPED_UNICODE));

                    return $this->response('', 401, 'Unauthorized', '请求要求用户的身份认证');
                }

                if (Request::isGet()) {
                    return Authorize::request(true);
                }

                $this->logcat('error', 'Authority::checkChannel(401 ' . __LINE__ . ') Unauthorized Channel() ' . json_encode($channel, JSON_UNESCAPED_UNICODE));

                return $this->response('', 401, 'Unauthorized', '请求要求用户的身份认证');
            }

            $this->session->set('expiretime', time() + (int)round(abs($this->expire)));

            if ($channel[AuthInfo::$modifier] == AuthInfo::$default) {
                $this->logcat('info', '默认权限，仅登录即可：' . $this->getIdentifier());
                return $this->response('', 200);
            } elseif (!Authorize::isUnion()) {
                // 获取联合授权
                if (Request::isAjax()) {
                    $this->logcat('error', 'Authority::checkChannel(407 ' . __LINE__ . ') Ajax Proxy Authentication Required Channel() ' . json_encode($channel, JSON_UNESCAPED_UNICODE));

                    $response = $this->response('', 407);
                }

                if (Request::isGet()) {
                    return Authorize::authentication(Config::get('auth.appid'), Request::url(true));
                }

                return AuthUnion::request(true);

                $this->logcat('error', 'Authority::checkChannel(407 ' . __LINE__ . ') Proxy Authentication Required Channel() ' . json_encode($channel, JSON_UNESCAPED_UNICODE));

                return $this->response('', 407);
            } else {

                try {
                    //TODO：授权信息查询，存在BUG，无法隔离App
                    $union = Db::name('union')
                        ->field(true)
                        // ->where("appid", "=", $this->appid)
                        ->where('uid', '=', $this->session->get('uid'))
                        ->where('unionid', '=', $this->session->get('union.unionid', 404))
                        // ->where("roleid", "=", $this->session->get("union.roleid", 404))
                        ->order('subtime desc')
                        ->cache(false)
                        ->find();
                    // 查询角色信息 * 可删除
                    $role = Db::name('role')
                        ->field(true)
                        ->where('roleid', '=', $this->session->get('union.roleid', 404))
                        ->order('subtime desc')
                        ->cache(false)
                        ->find();

                    // 根据当前频道查询可访问的方法
                    // @todo AppId 存在Bug
                    $access = Db::name('access')
                        ->field(true)
                        ->where('roleid', '=', $this->session->get('union.roleid', 404))
                        // ->where("appid", "=", $this->appid)
                        ->where('channelid', '=', $channel['channelid'])
                        ->order('subtime desc')
                        ->cache(false)
                        ->find();

                    if (!empty($access) && $access['status'] == 1 && $access['allow'] == 1 && stripos($access['method'], Request::method()) != false) {
                        $this->logcat('info', 'Authority::Check(Success::' . Request::method() . ' ' . __LINE__ . ')' . Request::url(true));
                        $response = $this->response('', 200);
                    } elseif (Authorize::isAdmin()) {
                        $this->logcat('debug', 'Authority::Check(Super Manager has Method[' . Request::method() . ' ' . __LINE__ . '] privileges)');
                        $response = $this->response('', 200);
                    } elseif (!empty($access) && $access['status'] == 1 && $access['allow'] != 1) {
                        $this->logcat('debug', 'Authority::Check(Allow ' . __LINE__ . ')  ' . json_encode($access, JSON_UNESCAPED_UNICODE));

                        $response = $this->response('', 402, 'Insufficient authority', '权限不足，无法访问该页面');
                    } elseif (Request::isAjax() && !empty($access) && $access['status'] == 1 && stripos($access['method'], 'ajax') == false) {
                        $this->logcat('error', 'Authority::checkChannel(405 ' . __LINE__ . ') Ajax Method Not Allowed ' . json_encode($access, JSON_UNESCAPED_UNICODE));

                        $response = $this->response('', 405, 'Ajax Method Not Allowed', '该页面禁止Ajax请求');
                    } elseif (!empty($access) && $access['status'] == 1 && stripos($access['method'], Request::method()) == false) {
                        $this->logcat('error', 'Authority::checkChannel(405 ' . __LINE__ . ') ' . Request::method() . ' Method Not Allowed ' . json_encode($access, JSON_UNESCAPED_UNICODE));

                        $response = $this->response('', 405, Request::method() . ' Method Not Allowed', '该页面禁止' . Request::method() . '请求');
                    } elseif (empty($access) || $access['status'] != 1) {
                        $this->logcat('error', 'Authority::checkChannel(407 ' . __LINE__ . ') Invalid authorization information');
                        $this->logcat('error', 'Access:' . json_encode($access, JSON_UNESCAPED_UNICODE));
                        $this->logcat('error', 'Union:' . json_encode($union, JSON_UNESCAPED_UNICODE));
                        $this->logcat('error', 'Channel:' . json_encode($channel, JSON_UNESCAPED_UNICODE));

                        $response = $this->response('', 407, 'Invalid authorization information', '无效的授权信息');
                    } else {
                        $this->logcat('error', 'Authority::checkChannel(406 ' . __LINE__ . ') Not Acceptable ' . json_encode($access, JSON_UNESCAPED_UNICODE));

                        $response = $this->response('', 406, 'Not Acceptable', '授权信息异常');
                    }
                } catch (DataNotFoundException $e) {
                    $this->logcat('error', 'Authority::Check(DataNotFoundException ' . __LINE__ . ')' . $e->getMessage());

                    $response = $this->response('', 500, 'DataNotFoundException:' . $e->getMessage(), '服务异常');
                } catch (ModelNotFoundException $e) {
                    $this->logcat('error', 'Authority::Check(ModelNotFoundException ' . __LINE__ . ')' . $e->getMessage());

                    $response = $this->response('', 500, 'ModelNotFoundException:' . $e->getMessage(), '服务异常');
                } catch (DbException $e) {
                    $this->logcat('error', 'Authority::Check(DbException ' . __LINE__ . ')' . $e->getMessage());

                    $response = $this->response('', 500, 'DbException:' . $e->getMessage(), '服务异常');
                }
            }
            if (!empty($this->after_handle)) {
                call_user_func_array($this->after_handle, array());
            }

            return $response;
        }

        /**
         * 初始化
         *
         */
        protected function initialize(): void
        {

        }

        /**
         * 获取访问标识符
         * 权限标识符（Identifier）推荐使用 resource:action 形式命名，如 email:login
         *
         * @return string
         */
        abstract function getIdentifier(): string;

        /**
         * 获取内部排除项
         *
         * @return array
         */
        private function internalIgnore(): array
        {
            return array_merge($this->getIgnore(), array(
                'index:index:index',
                'portal:*'
            ));
        }

        /**
         * 获取排除项
         *
         * @return array
         */
        abstract function getIgnore(): array;

        /**
         * 验证频道
         *
         * @return bool
         */
        abstract function has_channel(): bool;

        /**
         *验证角色
         *
         * @return bool
         */
        abstract function has_role(): bool;

        /**
         * 验证联合授权
         *
         * @return bool
         */
        abstract function has_union(): bool;

        /**
         * 验证权限
         *
         * @return bool
         */
        abstract function has_permission(): bool;

        /**
         * 请求重定向
         *
         * @param string $url 重定向地址
         * @param int $code 状态码
         *
         */
        abstract function redirect(string $url = '', int $code = 302);

        abstract function response($data, $code = 200, $status = '', $msg = '', $type = 'html');

        public function logcat($level, $message, array $context = []): void
        {
        }

        /**
         * 1、获取当前频道信息
         * 2、验证当前角色是否拥有该频道的访问权限
         * 3、
         */
        public function verify(): void
        {

        }

    }
