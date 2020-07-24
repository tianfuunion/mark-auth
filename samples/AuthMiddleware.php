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

use mark\auth\Authorize;
use mark\auth\middleware\Authority;
use mark\response\Responsive;
use app\account\model\User;

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

        // script("jquery-2.2.4.min", "open","//open.tianfu.ink/libs/jquery/script");
        // script("jquery-ui.min", "open","//open.tianfu.ink/libs/jquery/script");
        // script("jquery.session.min", "open","//open.tianfu.ink/libs/jquery/script");
        // script("jquery.cookie", "open", "//open.tianfu.ink/libs/jquery/script");
        // script("jquery.bxslider", "open","//open.tianfu.ink/libs/jquery/script");
        // script("jquery.simplesidebar", "open","//open.tianfu.ink/libs/jquery/script");
        // script("jquery.lazyload.min",,"open","//open"lazyload/script");
        // script(lazysizes.min,"open","lazyload/script");
        style('amazeui', 'open', '//open.tianfu.ink/libs/amazeui/style');

        style('weui.min', 'open', '//open.tianfu.ink/libs/weui/style');
        style('jquery-weui.min', 'open', '//open.tianfu.ink/libs/weui/style');

        script('weui.min', 'open', '//open.tianfu.ink/libs/weui/script');
        script('jquery-weui.min', 'open', '//open.tianfu.ink/libs/weui/script');
        script('fastclick', 'open', '//open.tianfu.ink/libs/weui/script');

        style('commons', 'open', '//open.tianfu.ink/libs/style');
        style('auto', 'open', '//open.tianfu.ink/libs/style');

        $appname = app('http')->getname();
        style($appname === 'index' ? 'portal' : $appname, 'open', '//open.tianfu.ink/libs/style');
        View::assign('appname', $appname);

        $this->request->appname = $appname;

        style(
            strtolower($this->request->controller()) === 'index' ? 'portal' : strtolower($this->request->controller()),
            'open', '//open.tianfu.ink/libs/style'
        );

        style('account', 'open', '//open.tianfu.ink/libs/style');
        style('console', 'open', '//open.tianfu.ink/libs/style');
        style('navigation-responsive', 'open', '//open.tianfu.ink/libs/style');
        style('header-responsive', 'open', '//open.tianfu.ink/libs/style');

        style('mark.collapse', 'open', '//open.tianfu.ink/libs/collapse/style');
        script('mark.collapse', 'open', '//open.tianfu.ink/libs/collapse/script');

        // style("amazeui", "open", "//open.tianfu.ink/libs/amazeui/style");
        // style("admin", "open", "//open.tianfu.ink/libs/amazeui/style");
        // style("app", "open", "//open.tianfu.ink/libs/amazeui/style");

        // script("amazeui.min", "open", "//open.tianfu.ink/libs/amazeui/script");
        // script("app", "open", "//open.tianfu.ink/libs/amazeui/script");
        // script("iscroll", "open", "//open.tianfu.ink/libs/amazeui/script");

        // style("mark.table", "open", "//open.tianfu.ink/libs/table/style");
        // style("mark.form", "open", "//open.tianfu.ink/libs/validform/style");
        // script("mark.min", "open", "//open.tianfu.ink/libs/mark/script");
        script('mark', 'open', '//open.tianfu.ink/libs/mark/script');
        script("mark.verify", "open", "//open.tianfu.ink/libs/validform/script");
        // script("mark.multipicker", "open", "//open.tianfu.ink/libs/validform/script");
        // style("mark.treeview", "open", "//open.tianfu.ink/libs/treeview/style");
        // script("mark.treeview", "open", "//open.tianfu.ink/libs/treeview/script");

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
     * @return bool
     */
    protected function has_channel(): bool {
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

    protected function onAuthorized($userInfo): void {
        $this->logcat('debug', 'AuthMiddleware::onAuthorized(UserInfo)' . json_encode($userInfo, JSON_UNESCAPED_UNICODE));

        if ($userInfo && is_array($userInfo) && isset($userInfo['openid']) && !empty($userInfo['openid'])) {
            // @todo 此处获取到微信UserInfo，请使用本地请求，用户登录数据
            $user = User::weChatAuth($userInfo);
        } elseif (!empty($userInfo) && is_array($userInfo) && isset($userInfo['uuid'])) {
            // @todo 临时办法,解决方案为直接将获取到的UserInfo存储到Session中
            $user = User::loginAgent(array('uid' => $userInfo['uuid']));
        }

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
            'AuthMiddleware:'
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

}