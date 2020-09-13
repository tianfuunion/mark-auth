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
use think\facade\Cookie;
use think\facade\Log;
use think\facade\View;

use mark\auth\Authorize;
use mark\auth\middleware\Authority;
use mark\response\Responsive;
use mark\system\Os;

/**
 * Class AuthCheck
 *
 * @todo    AppID的有效范围，
 *
 * @package app
 */
class AuthMiddleware extends Authority {

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
        // $this->setCache($this->app->cache);

        $handler = Cache::handler();
        // $this->setCache($handler);

        $instance = Cache::instance();
        // $this->setCache($instance);

        parent::__construct();
    }

    /**
     * Session初始化
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

        /**
         * @todo 排除验证码,临时办法
         */
        if (stripos($request->server('request_uri'), 'captcha') !== false || $request->server('request_uri') == '/') {
            return $next($request);
        }

        $result = parent::handler();
        if ($result instanceof Response) {
            $this->logcat('debug', 'AuthMiddleware::handle（Response Redirect）' . $this->getIdentifier());

            return $result;
        }
        if (is_array($result) && !empty($result['code'])) {
            $this->logcat('debug', 'AuthMiddleware::handler(' . $this->getIdentifier() . ')' . json_encode($result, JSON_UNESCAPED_UNICODE));

            switch ($result["code"]) {
                case 200:
                    // 正常
                    return $next($request);
                    break;
                case 302:
                    // 跳转
                    return redirect($result['data']);
                    break;
                case 401:
                    // 认证
                    return Responsive::display($result['data'], $result['code'], $result['status'], $result['msg'], $result['type']);
                    break;
                case 404:
                    // 错误
                    return Responsive::display($result['data'], $result['code'], $result['status'], $result['msg'], $result['type']);
                    break;
                case 412:
                    // 无效
                    return Responsive::display($result['data'], $result['code'], $result['status'], $result['msg'], $result['type']);
                    break;
                case 503:
                    // 维护
                    return Responsive::display($result['data'], $result['code'], $result['status'], $result['msg'], $result['type']);
                    break;
                default:
                    // 异常
                    return Responsive::display($result['data'], $result['code'], $result['status'], $result['msg'], $result['type']);
                    break;
            }
        }
        $this->logcat('error', 'AuthMiddleware::handler(Not Code ' . $this->getIdentifier() . ')' . json_encode($result, JSON_UNESCAPED_UNICODE));

        return $next($request);
    }

    /**
     * 初始化
     *
     */
    protected function initialize(): void {
        // registerFilter("output", "compress_html");
        // register_function("autoversion","autoversion");

        // script("jquery-2.2.4.min", "open","https://res.tianfu.pub/jquery/script");
        // script("jquery-ui.min", "open","https://res.tianfu.pub/jquery/script");
        // script("jquery.session.min", "open","https://res.tianfu.pub/jquery/script");
        // script("jquery.cookie", "open", "https://res.tianfu.pub/jquery/script");
        // script("jquery.bxslider", "open","https://res.tianfu.pub/jquery/script");
        // script("jquery.simplesidebar", "open","https://res.tianfu.pub/jquery/script");
        // script("jquery.lazyload.min",,"open","//open"lazyload/script");
        // script(lazysizes.min,"open","lazyload/script");

        style('amazeui', 'open', 'https://res.tianfu.pub/amazeui/style');

        style('weui.min', 'open', 'https://res.tianfu.pub/weui/style');
        style('jquery-weui.min', 'open', 'https://res.tianfu.pub/weui/style');

        script('weui.min', 'open', 'https://res.tianfu.pub/weui/script');
        script('jquery-weui.min', 'open', 'https://res.tianfu.pub/weui/script');
        script('fastclick', 'open', 'https://res.tianfu.pub/weui/script');

        style('commons', 'open');
        style('auto', 'open');

        $appname = app('http')->getname();
        style($appname === 'index' ? 'portal' : $appname, 'open');
        View::assign('appname', $appname);

        $this->request->appname = $appname;

        style($this->request->controller(true) === 'index' ? 'portal' : $this->request->controller(true), 'open');

        style('account', 'open');
        style('console', 'open');
        style('navigation-responsive', 'open');
        style('header-responsive', 'open');

        style('mark.collapse', 'open', 'https://res.tianfu.pub/collapse/style');
        script('mark.collapse', 'open', 'https://res.tianfu.pub/collapse/script');

        // style("amazeui", "open", "https://res.tianfu.pub/amazeui/style");
        // style("admin", "open", "https://res.tianfu.pub/amazeui/style");
        // style("app", "open", "https://res.tianfu.pub/amazeui/style");

        // script("amazeui.min", "open", "https://res.tianfu.pub/amazeui/script");
        // script("app", "open", "https://res.tianfu.pub/amazeui/script");
        // script("iscroll", "open", "https://res.tianfu.pub/amazeui/script");

        // style("mark.table", "open", "https://res.tianfu.pub/table/style");
        // style("mark.form", "open", "https://res.tianfu.pub/validform/style");
        // script("mark.min", "open", "https://res.tianfu.pub/mark/script");
        script('mark', 'open', 'https://res.tianfu.pub/mark/script');
        script("mark.verify", "open", "https://res.tianfu.pub/validform/script");
        // script("mark.multipicker", "open", "https://res.tianfu.pub/validform/script");
        // style("mark.treeview", "open", "https://res.tianfu.pub/treeview/style");
        // script("mark.treeview", "open", "https://res.tianfu.pub/treeview/script");

        if (Config::has('app.iconfont')) {
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
        }
    }

    /**
     * 获取访问标识符
     *
     * @return string
     */
    protected function getIdentifier(): string {
        return app('http')->getName(true) . ":" . $this->request->controller(true) . ":" . $this->request->action(true);
    }

    /**
     * 获取排除项
     *
     * @return array
     */
    protected function getIgnore(): array {
        return Config::get('auth.ignore', array());
    }

    /**
     * 是否排除当前标识符，中间件可重写本方法来自定义排除算法
     *
     * @param string $identifier
     *
     * @return bool
     */
    protected function has_exclude(string $identifier): bool {
        $this->logcat('info', 'AuthMiddleware::has_exclude(' . $identifier . ')');

        if (stripos($identifier, 'captcha') !== false || stripos($identifier, '/') !== false) {
            return true;
        }

        return parent::has_exclude($identifier);
    }

    /**
     * 验证频道
     *
     * @param string $identifier
     *
     * @return bool
     */
    protected function has_channel(string $identifier): bool {
        if (!empty($identifier)) {
            return true;
        }

        return false;
    }

    /**
     * 验证角色
     *
     * @return bool|void
     */
    protected function has_role(): bool {
        return $this->session->has("union.role");
    }

    /**
     * 验证联合授权
     *
     * @return bool
     */
    protected function has_union(): bool {
        return $this->session->has("union");
    }

    /**
     * 验证权限
     *
     * @return bool
     */
    protected function has_permission(): bool {
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
    protected function redirect(string $url = '', int $code = 302) {
        return redirect($url, $code);
    }

    protected function response($data, $code = 200, $status = '', $msg = '', $type = 'html') {
        // return Responsive::display($data, $code, $status, $msg, $type);
        return array('data' => $data, 'code' => $code, 'status' => $status, 'msg' => $msg, 'type' => $type);
    }

    protected function onAuthorized(array $userInfo): void {
        if ($userInfo && is_array($userInfo) && isset($userInfo['openid']) && !empty($userInfo['openid'])) {
            // @todo 此处获取到微信UserInfo，请使用本地请求，用户登录数据(此处应统一为UnionInfo)，
            // $user = User::weChatAuth($userInfo);
            $this->session->set('user_wechat', $userInfo);
        }
        if (!empty($userInfo) && is_array($userInfo) && isset($userInfo['uuid'])) {
            // @todo 临时办法,解决方案为直接将获取到的UserInfo存储到Session中
            // $user = User::loginAgent(array('uid' => $userInfo['uuid']));
            $this->session->set('user_info', $userInfo);
        }
        foreach ($userInfo as $key => $item) {
            if ($key === 'avatar') {
                $this->session->set($key, basename($item));
                Cookie::set($key, basename($item));
            } else {
                $this->session->set($key, $item);
                if (!is_array($item)) {
                    Cookie::set($key, (string)$item);
                }
            }
        }

        $this->session->delete('password');
        $this->session->set(Authorize::$login, 1);
        $this->session->set(Authorize::$isLogin, 1);
        $this->session->set(Authorize::$expiretime, $this->request->time() + Config::get('auth.expire', 1440));

        Cookie::delete('password');
        Cookie::set(Authorize::$login, "1");
        Cookie::set(Authorize::$isLogin, "1");
        Cookie::set(Authorize::$expiretime, (string)($this->request->time() + (int)Config::get('auth.expire', 1440)));
        Cookie::set("TF_Cookie", $this->session->getId(), array('domain' => "tianfu.ink"));
    }

    public function logcat($level, $message, array $context = []): void {
        if ($this->app->isDebug() && Authorize::isAdmin() && Authorize::isUnion() && Authorize::isTesting()) {

        }
        if ($this->app->isDebug()) {
            Log::log($level, $message, $context);
        }
    }

    protected function cache() {
        return cache();
    }

    protected function onDestroy() {

    }

    public function end(Response $response) {
        $this->logcat(
            'debug',
            "\nAuthMiddleware:"
            . "\nAgent：" . Os::getAgent()
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
            . "\nRequest:" . json_encode($this->request->param(), JSON_UNESCAPED_UNICODE)
            . "\n"
        );
    }

}