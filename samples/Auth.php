<?php

    declare (strict_types=1);

    namespace app;

    use Closure;
    use think\App;
    use think\Session;
    use think\Request;
    use think\Response;

    use think\facade\Cache;
    use think\facade\Config;
    use think\facade\Db;
    use think\facade\Log;
    use think\facade\View;

    use think\db\exception\DataNotFoundException;
    use think\db\exception\ModelNotFoundException;
    use think\db\exception\DbException;

    use mark\src\entity\AuthInfo;
    use mark\src\AuthUnion;
    use mark\src\Authorize;

    use mark\response\Responsive;
    use mark\system\Os;
    use mark\wechat\Jssdk;
    use mark\src\middleware\Authority;

    /**
     * Class AuthCheck
     * for ThinkPHP
     * @todo    AppID的有效范围，
     *
     * @package app
     */
    class Auth extends Authority {

        /** @var App */
        protected $app;
        /** @var Request */
        protected $request;
        /** @var Session */
        protected $session;

        public function __construct(App $app, Session $session) {
            $this->app = $app;
            $this->session = $session;

            $this->setPoolId(Config::get('auth.poolid'));
            $this->setAppId(Config::get('auth.appid'));

            $this->setDebug($this->app->isDebug());
            // $this->setCache($this->request->param('cache', true));
            $this->setCache(Cache());

            parent::__construct();
        }

        /**
         * Session初始化
         *
         * @access public
         *
         * @param Request $request
         * @param Closure $next
         *
         * @return Response
         */
        public function handle($request, Closure $next) {
            $this->request = $request;

            // AuthUnion 初始化
            $this->initialize();

            /** @var Response $response */
            // $response = $next($request);
            if (!Authorize::isAdmin() || !Authorize::isTesting()) {
                return $next($request);
            }

            $result = parent::handler();
            switch ($result["code"]) {
                case 200:
                    // 正常
                    break;
                case 302:
                    // 跳转
                    break;
                case 404:
                    // 错误
                    break;
                default:
                    // 异常
                    break;
            }

            /**
             * 排除验证码
             */
            if (
                stripos($request->server('request_uri'), 'captcha') !== false ||
                $request->server('request_uri') === '/') {
                // return $response;
                return $next($request);
            }

            // todo:随后数据来源可从数据库中获取
            $ignore = Config::get('auth.ignore');
            if (!empty($ignore) && is_array($ignore)) {
                foreach ($ignore as $key => $item) {
                    if (stripos(rtrim($request->server('request_uri'), "/"), $item)) {
                        // return $response;
                        return $next($request);
                    }
                }
            }

            if ($this->request->has('cache')) {
                $cache = $request->param('cache', 0);
            } elseif ($this->app->isDebug()) {
                $cache = 0;
            } else {
                $cache = 1;
            }

            $result = $this->channel->getChannel(Config::get('auth.appid'), rtrim($request->server('document_uri'), "/"), $cache);

            if (Authorize::isAdmin() || Authorize::isTesting()) {
                $identifier = $this->channel->getIdentifier(
                    Config::get('auth.poolid'),
                    Config::get('auth.appid'),
                    $this->getIdentifier(),
                    $cache
                );
                if (Authorize::isTesting()) {
                    $result = $identifier;
                }
            }

            if (!empty($result)) {
                if (is_string($result)) {
                    $result = json_decode($result, true);
                }
                switch ($result['code']) {
                    case 200:
                        $channel = $result['data'];
                        break;
                    default:
                        return Responsive::display($result['data'], $result['code'], $result['status'], $result['msg']);
                        break;
                }
            } else {
                log::error('Result:' . json_encode($result, JSON_UNESCAPED_UNICODE));

                return Responsive::display('', 503);
            }

            if (Authorize::isAdmin()) {
                log::debug('AuthUnion::Check(Super Manager has Channel privileges)');
            } elseif (!empty($channel)) {
                if ($channel['status'] !== 1) {
                    Log::error('AuthUnion::checkChannel(501 ' . __LINE__ . ') Channel information not available');
                    Log::error('Channel() ' . json_encode($channel, JSON_UNESCAPED_UNICODE));

                    return Responsive::display('', 503, 'Channel information not available', '该频道尚未启用');
                }
            } else {
                Log::error('AuthUnion::checkChannel(412 ' . __LINE__ . ') Invalid Channel information');
                Log::error('Channel() ' . json_encode($channel, JSON_UNESCAPED_UNICODE));
                Log::error('Server() ' . json_encode($request->server(), JSON_UNESCAPED_UNICODE));

                return Responsive::display('', 412, 'Invalid Channel information ', '无效的频道信息');
            }

            // 不为公开则必检查* 检查频道是否需要权限检查
            if ($channel[AuthInfo::$modifier] === AuthInfo::$public) {
                // 该页面为公开页面，无需检查
                // return $response;
                return $next($request);
            }

            // 更新用户登录有效期
            if (Authorize::isLogin()) {
                $this->session->set('expiretime', $request->time() + (int)round(abs(Config::get("auth.expire", 1440))));
            } else {
                if ($request->isAjax() || $request->isPjax()) {
                    Log::error('AuthUnion::checkChannel(401 ' . __LINE__ . ') Ajax Unauthorized');
                    Log::error('Channel() ' . json_encode($channel, JSON_UNESCAPED_UNICODE));

                    return Responsive::display('', 401, 'Unauthorized', '请求要求用户的身份认证');
                }

                if ($request->isGet()) {
                    return Authorize::request(true);
                }

                Log::error('AuthUnion::checkChannel(401 ' . __LINE__ . ') Unauthorized');
                Log::error('Channel() ' . json_encode($channel, JSON_UNESCAPED_UNICODE));

                return Responsive::display('', 401, 'Unauthorized', '请求要求用户的身份认证');
            }

            if ($channel[AuthInfo::$modifier] === AuthInfo::$default) {
                // return $response;
                return $next($request);
            }

            // 不为默认则必获取授权
            if (!Authorize::isUnion()) {
                if ($request->isAjax()) {
                    Log::error('AuthUnion::checkChannel(407 ' . __LINE__ . ') Ajax Proxy Authentication Required');
                    Log::error('Channel() ' . json_encode($channel, JSON_UNESCAPED_UNICODE));

                    return Responsive::display('', 407);
                }

                if ($request->isGet()) {
                    return AuthUnion::request(true);
                }

                Log::error('AuthUnion::checkChannel(407 ' . __LINE__ . ') Proxy Authentication Required');
                Log::error('Channel() ' . json_encode($channel, JSON_UNESCAPED_UNICODE));

                return Responsive::display('', 407);
            }

            try {
                //TODO：授权信息查询，存在BUG，无法隔离App
                $union = Db::name('union')
                    ->field(true)
                    // ->where("appid", "=", Config::get("auth.appid"))
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
                    // ->where("appid", "=", Config::get("auth.appid"))
                    ->where('channelid', '=', $channel['channelid'])
                    ->order('subtime desc')
                    ->cache(false)
                    ->find();

                // Log::error("Union() " . json_encode($union, JSON_UNESCAPED_UNICODE));
                // Log::error("Role() " . json_encode($role, JSON_UNESCAPED_UNICODE));
                // Log::error("Access() " . json_encode($access, JSON_UNESCAPED_UNICODE));

                if (
                    !empty($access) && $access['status'] === 1
                    && $access['allow'] === 1
                    && stripos($access['method'], $request->method()) !== false) {
                    log::info('AuthUnion::Check(Success::' . $request->method() . ' ' . __LINE__ . ')' . $request->url(true));
                } elseif (Authorize::isAdmin()) {
                    log::debug('AuthUnion::Check(Super Manager has Method[' . $request->method() . ' ' . __LINE__ . '] privileges)');
                } elseif (!empty($access) && $access['status'] === 1 && $access['allow'] !== 1) {
                    Log::debug('AuthUnion::Check(Allow ' . __LINE__ . ') ');
                    Log::error('Access() ' . json_encode($access, JSON_UNESCAPED_UNICODE));

                    return Responsive::display('', 402, 'Insufficient authority', '权限不足，无法访问该页面');
                } elseif ($request->isAjax() && !empty($access) && $access['status'] === 1 && stripos($access['method'], 'ajax') === false) {
                    Log::error('AuthUnion::checkChannel(405 ' . __LINE__ . ') Ajax Method Not Allowed ');
                    Log::error('Access() ' . json_encode($access, JSON_UNESCAPED_UNICODE));

                    return Responsive::display('', 405, 'Ajax Method Not Allowed', '该页面禁止Ajax请求');
                } elseif (!empty($access) && $access['status'] === 1 && stripos($access['method'], $request->method()) === false) {
                    Log::error('AuthUnion::checkChannel(405 ' . __LINE__ . ') ' . $request->method() . ' Method Not Allowed ');
                    Log::error('Access() ' . json_encode($access, JSON_UNESCAPED_UNICODE));

                    return Responsive::display(
                        '', 405, $request->method() . ' Method Not Allowed', '该页面禁止' . $request->method() . '请求'
                    );
                } elseif (empty($access) || $access['status'] !== 1) {
                    Log::error('AuthUnion::checkChannel(407 ' . __LINE__ . ') Invalid authorization information');
                    Log::error('Access:' . json_encode($access, JSON_UNESCAPED_UNICODE));
                    Log::error('Union:' . json_encode($union, JSON_UNESCAPED_UNICODE));
                    Log::error('Channel:' . json_encode($channel, JSON_UNESCAPED_UNICODE));

                    return Responsive::display('', 407, 'Invalid authorization information', '无效的授权信息');
                } else {
                    Log::error('AuthUnion::checkChannel(406 ' . __LINE__ . ') Not Acceptable ');
                    Log::error('Access() ' . json_encode($access, JSON_UNESCAPED_UNICODE));

                    return Responsive::display('', 406, 'Not Acceptable', '授权信息异常');
                }
            } catch (DataNotFoundException $e) {
                Log::error('AuthUnion::Check(DataNotFoundException ' . __LINE__ . ')' . $e->getMessage());

                return Responsive::display('', 500, 'DataNotFoundException:' . $e->getMessage(), '服务异常');
            } catch (ModelNotFoundException $e) {
                Log::error('AuthUnion::Check(ModelNotFoundException ' . __LINE__ . ')' . $e->getMessage());

                return Responsive::display('', 500, 'ModelNotFoundException:' . $e->getMessage(), '服务异常');
            } catch (DbException $e) {
                Log::error('AuthUnion::Check(DbException ' . __LINE__ . ')' . $e->getMessage());

                return Responsive::display('', 500, 'DbException:' . $e->getMessage(), '服务异常');
            }

            // return $response;
            return $next($request);
        }

        /**
         * 初始化
         *
         */
        protected function initialize(): void {
            // registerFilter("output", "compress_html");
            // register_function("autoversion","autoversion");

            // script("jquery-2.2.4.min", "open","https://open.tianfu.ink/libs/jquery/script");
            // script("jquery-ui.min", "open","https://open.tianfu.ink/libs/jquery/script");
            // script("jquery.session.min", "open","https://open.tianfu.ink/libs/jquery/script");
            // script("jquery.cookie", "open", "https://open.tianfu.ink/libs/jquery/script");
            // script("jquery.bxslider", "open","https://open.tianfu.ink/libs/jquery/script");
            // script("jquery.simplesidebar", "open","https://open.tianfu.ink/libs/jquery/script");
            // script("jquery.lazyload.min",,"open","open"lazyload/script");
            // script(lazysizes.min,"open","lazyload/script");
            style('amazeui', 'open', 'https://open.tianfu.ink/libs/amazeui/style');

            style('weui.min', 'open', 'https://open.tianfu.ink/libs/weui/style');
            style('jquery-weui.min', 'open', 'https://open.tianfu.ink/libs/weui/style');

            script('weui.min', 'open', 'https://open.tianfu.ink/libs/weui/script');
            script('jquery-weui.min', 'open', 'https://open.tianfu.ink/libs/weui/script');
            script('fastclick', 'open', 'https://open.tianfu.ink/libs/weui/script');

            style('commons', 'open', 'https://open.tianfu.ink/libs/style');
            style('auto', 'open', 'https://open.tianfu.ink/libs/style');

            $appname = app('http')->getname();
            style($appname === 'index' ? 'portal' : $appname, 'open', 'https://open.tianfu.ink/libs/style');
            View::assign('appname', $appname);

            $this->request->appname = $appname;

            style(
                strtolower($this->request->controller()) === 'index' ? 'portal' : strtolower($this->request->controller()),
                'open', 'https://open.tianfu.ink/libs/style'
            );

            style('account', 'open', 'https://open.tianfu.ink/libs/style');
            style('console', 'open', 'https://open.tianfu.ink/libs/style');
            style('navigation-responsive', 'open', 'https://open.tianfu.ink/libs/style');
            style('header-responsive', 'open', 'https://open.tianfu.ink/libs/style');

            style('mark.collapse', 'open', 'https://open.tianfu.ink/libs/collapse/style');
            script('mark.collapse', 'open', 'https://open.tianfu.ink/libs/collapse/script');

            // style("amazeui", "open", "https://open.tianfu.ink/libs/amazeui/style");
            // style("admin", "open", "https://open.tianfu.ink/libs/amazeui/style");
            // style("app", "open", "https://open.tianfu.ink/libs/amazeui/style");

            // script("amazeui.min", "open", "https://open.tianfu.ink/libs/amazeui/script");
            // script("app", "open", "https://open.tianfu.ink/libs/amazeui/script");
            // script("iscroll", "open", "https://open.tianfu.ink/libs/amazeui/script");

            // style("mark.table", "open", "https://open.tianfu.ink/libs/table/style");
            // style("mark.form", "open", "https://open.tianfu.ink/libs/validform/style");
            // script("mark.min", "open", "https://open.tianfu.ink/libs/mark/script");
            script('mark', 'open', 'https://open.tianfu.ink/libs/mark/script');
            script("mark.verify", "open", "https://open.tianfu.ink/libs/validform/script");
            // script("mark.multipicker", "open", "https://open.tianfu.ink/libs/validform/script");
            // style("mark.treeview", "open", "https://open.tianfu.ink/libs/treeview/style");
            // script("mark.treeview", "open", "https://open.tianfu.ink/libs/treeview/script");

            // style("font_279187_w2z80q86isb", "open", "https://at.alicdn.com/t");
            // script("font_279187_w2z80q86isb", "open", "https://at.alicdn.com/t");

            foreach (Config::get('app.iconfont') as $key => $item) {
                switch ($item['type']) {
                    case 'style':
                        style($item['name'], 'open', $item['url']);
                        break;
                    case 'script':
                        script($item['name'], 'open', $item['url']);
                        break;
                    default:
                        break;
                }
            }

            // 获取微信密钥：分享，
            if (Os::isWeChat() && Config::get('auth.stores.wechat.status', false)) {
                $jssdk = new Jssdk(Config::get('auth.stores.wechat.appid'), Config::get('auth.stores.wechat.secret'));
                $signPackage = $jssdk->GetSignPackage();
                \think\facade\Session::set("wxsign", $signPackage);
                View::assign("wxsign", $signPackage);
            }
            if (Authorize::isAdmin()) {
                Log::debug(
                    'RouterMiddleware::Authority()'
                    . "\nFile：" . __FILE__
                    . "\nDir：" . __DIR__
                    . "\nNameSpace：" . __NAMESPACE__
                    . "\nClass：" . __CLASS__
                    . "\nMethod：" . __METHOD__
                    . "\nFunction：" . __FUNCTION__
                    . "\nLine：" . __LINE__
                    . "\nTrait：" . __TRAIT__
                    . "\nisMobile：" . $this->request->isMobile()
                    . "\nAuth.AppID:" . Config::get('auth.appid')
                    . "\nUnion.AppID:" . $this->session->get('union.appid')
                    . "\nUnionID:" . $this->session->get('union.unionid')
                    . "\nRoldID:" . $this->session->get('union.roleid')
                    . "\nUUID:" . $this->session->get('union.uid')
                    . "\nStatus:" . $this->session->get('union.status')

                    . "\nProject：" . app('http')->getname()
                    . "\ncontroller：" . $this->request->controller()
                    . "\naction：" . $this->request->action()
                    . "\ntype：" . $this->request->type()
                    . "\ntime：" . $this->request->time()
                    . "\nrootDomain：" . $this->request->rootDomain()
                    . "\ndomain：" . $this->request->domain()
                    . "\nip：" . $this->request->ip()
                    . "\nisAjax：" . $this->request->isAjax()
                    . "\nis_ajax：" . is_ajax()
                    . "\nmethod：" . $this->request->method()
                    . "\nurl：" . $this->request->url()
                    . "\nurl：" . $this->request->url(true)
                );
            }

            $this->before_handle(
                function () {

                }
            );
            $this->after_handle(
                function () {
                }
            );
        }

        /**
         * 获取访问标识符
         *
         * @return string
         */
        public function getIdentifier(): string {
            return app('http')->getName(true) . ":" . $this->request->controller(true) . ":" . $this->request->action(true);
        }

        /**
         * 获取排除项
         *
         * @return array
         */
        public function getIgnore(): array {
            return Config::get('auth.ignore', array());
        }

        /**
         * 验证频道
         *
         * @return bool
         */
        public function has_channel(): bool {
            try {
                $channel = Db::name('app_channel')
                    ->field(true)
                    ->where('url', '=', rtrim($this->request->server('request_uri'), "/"))
                    ->cache(false)
                    ->find();
                if (!empty($channel)) {
                    $data['channel'] = $channel;

                    return true;
                }
            } catch (DataNotFoundException $e) {
            } catch (ModelNotFoundException $e) {
            } catch (DbException $e) {
            }

            return false;
        }

        /**
         *验证角色
         *
         * @return bool|void
         */
        public function has_role(): bool {
            return $this->session->has("union.role");
        }

        /**
         * 验证联合授权
         *
         * @return bool
         */
        public function has_union(): bool {
            return $this->session->has("union");
        }

        /**
         * 验证权限
         *
         * @return bool
         */
        public function has_permission(): bool {
            return $this->session->has("union.permission");
        }

        /**
         * 验证
         *
         * @param \think\Request $request
         */
        public function validate(Request $request) {

        }

        /**
         * 请求重定向
         *
         * @param string $url  重定向地址
         * @param int    $code 状态码
         *
         * @return \think\response\Redirect|void
         */
        public function redirect(string $url = '', int $code = 302) {
            return redirect($url, $code);
        }

        public function response($data, $code = 200, $status = '', $msg = '', $type = 'html') {
            return Responsive::display($data, $code, $status, $msg, $type);
        }

        public function logcat($level, $message, array $context = []): void {
            Log::log($level, $message, $context);
        }

        public function cache() {
            return cache();
        }

        /**
         * 1、获取当前频道信息
         * 2、验证当前角色是否拥有该频道的访问权限
         * 3、
         *
         */
        public function verify(): void {

        }

        public function onDestroy() {

        }

        public function end(Response $response) {
            if ($this->app->isDebug()) {
                Log::debug(
                    'Authority:'
                    . "\nFile：" . __FILE__
                    . "\nDir：" . __DIR__
                    . "\nNameSpace：" . __NAMESPACE__
                    . "\nClass：" . __CLASS__
                    . "\nMethod：" . __METHOD__
                    . "\nFunction：" . __FUNCTION__
                    . "\nLine：" . __LINE__
                    . "\nTrait：" . __TRAIT__
                    . "\nisMobile：" . $this->request->isMobile()
                    . "\nAuth.AppID:" . Config::get('auth.appid')
                    . "\nUnion.AppID:" . $this->session->get('union.appid')
                    . "\nUnionID:" . $this->session->get('union.unionid')
                    . "\nRoldID:" . $this->session->get('union.roleid')
                    . "\nUUID:" . $this->session->get('union.uid')
                    . "\nStatus:" . $this->session->get('union.status')

                    . "\nProject：" . app('http')->getname()
                    . "\ncontroller：" . $this->request->controller()
                    . "\naction：" . $this->request->action()
                    . "\ntype：" . $this->request->type()
                    . "\ntime：" . $this->request->time()
                    . "\nrootDomain：" . $this->request->rootDomain()
                    . "\ndomain：" . $this->request->domain()
                    . "\nip：" . $this->request->ip()
                    . "\nisAjax：" . $this->request->isAjax()
                    . "\nis_ajax：" . is_ajax()
                    . "\nmethod：" . $this->request->method()
                    . "\nurl：" . $this->request->url()
                    . "\nurl：" . $this->request->url(true)
                );
            }
            // $this->session->save();
        }

    }
