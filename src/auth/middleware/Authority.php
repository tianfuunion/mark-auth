<?php

declare (strict_types=1);

namespace mark\auth\middleware;

use think\facade\Config;
use think\facade\Request;
use think\response\Redirect;

use mark\auth\Authorize;
use mark\auth\entity\AuthInfo;
use mark\auth\model\Channel;
use mark\system\Os;

use Psr\SimpleCache\CacheInterface;

/**
 * Class Authority
 *
 * @package mark\auth\middleware
 */
abstract class Authority implements CacheInterface {

    /**
     * @var string
     */
    private $appid = '';
    /**
     * @var string
     */
    private $poolid = '';
    /**
     * @var string
     */
    private $secret = '';
    /**
     * @var string
     */
    protected $lang = 'zh-cn';
    /**
     * @var bool
     */
    protected $debug = false;
    /**
     * @var int
     */
    public $expire = 1440;

    /**
     * @var \mark\auth\model\Channel
     */
    protected $channel;

    /**
     * @var array
     */
    private $config;

    public function __construct() {
        $this->logcat('info', 'Authority::construct(' . Os::getAgent() . ')');
        Authorize::setCache($this);
        $this->channel = new Channel($this);
    }

    /**
     * @param $appid
     *
     * @return $this
     */
    protected final function setAppId($appid): Authority {
        $this->appid = $appid;

        return $this;
    }

    /**
     * @param $poolid
     *
     * @return $this
     */
    protected final function setPoolId($poolid): Authority {
        $this->poolid = $poolid;

        return $this;
    }

    /**
     * @param string $secret
     *
     * @return $this
     */
    protected final function setSecret(string $secret): Authority {
        $this->secret = $secret;

        return $this;
    }

    /**
     * @param string $lang
     *
     * @return $this
     */
    protected final function setLang(string $lang = 'zh-cn'): Authority {
        $this->lang = $lang;

        return $this;
    }

    /**
     * @param bool $debug
     *
     * @return $this
     */
    protected final function setDebug(bool $debug): Authority {
        $this->debug = $debug;

        return $this;
    }

    /**
     * @param int $expire
     *
     * @return $this
     */
    protected final function setExpire(int $expire): Authority {
        $this->expire = $expire;

        return $this;
    }

    /**
     * @param array $config
     *
     * @return $this
     */
    protected final function setConfig(array $config): Authority {
        $this->config = $config;

        return $this;
    }

    /**
     * 权限验证处理器
     *
     * @return array|bool|false|mixed|string|\think\response\Redirect
     * @throws \think\db\exception\DataNotFoundException
     * @throws \think\db\exception\DbException
     * @throws \think\db\exception\ModelNotFoundException
     */
    protected final function handler() {
        // 初始化
        $this->initialize();

        /**
         * @todo：1、获取频道标示符
         */
        $identifier = $this->getInternalIdentifier();
        if (empty($identifier)) {
            $this->logcat('error', '无效的频道标识符：' . $identifier . __LINE__);

            return $this->response($identifier, 404, '', '无效的频道标识符', 'json');
        }

        /**
         * @todo 2、排除自定义标识符：存在Bug，以下情况可能会排除
         */
        if ($this->has_exclude($identifier)) {
            $this->logcat('info', '自定义排除算法：' . $identifier);

            return $this->response('', 200, '', '', 'json');
        }

        /**
         * @todo 3、校验标识符，校验频道状态
         */
        $channel = $this->channel->getIdentifier($this->appid, $this->poolid, $identifier, $this->debug);

        if (empty($channel)) {
            $this->logcat('error', 'Authority::handler(channel::getIdentifier is null)' . __LINE__);
            $channel = $this->channel->getChannel($this->appid, rtrim(Request::server('document_uri'), "/"), $this->debug);
        }
        $this->logcat('info', 'Authority::handler(Channel Result)' . json_encode($channel, JSON_UNESCAPED_UNICODE));

        /**
         * @todo 4、管理员或测试员 不检查频道状态
         */
        if (Authorize::isAdmin() || Authorize::isTesting()) {
            $this->logcat('debug', 'Authority::handler(Check Super Manager has Channel privileges)' . $identifier);
        }

        if (empty($channel) || !isset($channel['channelid']) || empty($channel['channelid'])) {
            $this->logcat('error', 'Authority::handler(404 无效的频道信息)' . $identifier . __LINE__);

            return $this->response('', 404, 'Invalid Channel information ', '无效的频道信息');
        }
        if (!isset($channel['status']) || empty($channel['status']) || $channel['status'] != 1) {
            $this->logcat('error', 'Authority::handler(410 该频道尚未启用)' . $identifier . __LINE__);

            return $this->response('', 410, 'Channel information not available', '该频道尚未启用');
        }

        /**
         * @todo 5、检查频道是否需要权限检查：公开页面，无需检查
         */
        if (isset($channel[AuthInfo::$modifier]) && $channel[AuthInfo::$modifier] == AuthInfo::$public) {
            $this->logcat('info', '公开页面，无需检查：' . $identifier);

            return $this->response('', 200);
        }

        /**
         * @todo 6、校验异步请求
         */
        if (!Authorize::isLogin()) {
            if (is_ajax() || is_pjax()) {
                $this->logcat('error', 'Authority::handler(ajax checkChannel 401 身份认证)' . __LINE__);

                return $this->response('', 401, 'Ajax Unauthorized', '请求用户的身份认证', 'json');
            }

            if (!(is_get() || Request::isGet())) {
                $this->logcat('error', 'Authority::handler(401 身份认证)' . __LINE__);

                return $this->response('', 401, 'Unauthorized', '请求用户的身份认证');
            }

            if (Config::get('auth.level', 'slave') == 'master') {
                $this->logcat('debug', 'Authority::Redirect(Unauthorized 302 登录请求)');
                // $response = Authorize::request(true);
                // $url = Config::get('auth.host') . '/auth.php/login/login?callback=' . urlencode(Request::url(true));

                // return $this->response($url, 302, 'Unauthorized', '登录请求');
            }

            // $result = Authorize::dispenser(Config::get('auth.level', 'slave'));
            // $result = Authorize::dispenser(Config::get('auth.level', 'slave'), 'auth_union');
            // $result = Authorize::getClient(Config::get('auth.level', 'slave'))->request('auth_base');
            $result = Authorize::getClient(true)->authorize(
                $this->appid,
                $this->secret,
                Request::url(true),
                'code',
                'auth_base',
                '',
                $this->lang
            );

            $this->logcat('debug', 'Authority::handler(Authorize::dispenser)' . json_encode(!is_array($result) ? $result : '', JSON_UNESCAPED_UNICODE));

            if ($result instanceof Redirect) {
                $this->logcat('debug', 'Authority::handler(Authorize::dispenser instanceof Redirect)');

                return $result;
            }
            if (!empty($result) && is_array($result) && isset($result['openid']) && !empty($result['openid'])) {
                $this->logcat('debug', 'Authority::handler(UserInfo)' . json_encode($result, JSON_UNESCAPED_UNICODE));

                $this->onAuthorized($result);
            } else {
                $this->logcat('error', 'Authority::handler(Request::Param)' . __LINE__ . json_encode(Request::param()));
            }
        }

        /**
         * @todo 7、检查频道是否需要权限检查：默认权限，仅登录即可
         */
        if (isset($channel[AuthInfo::$modifier]) && $channel[AuthInfo::$modifier] == AuthInfo::$default) {
            $this->logcat('info', '默认权限，仅登录即可：' . $identifier);

            return $this->response('', 200);
        }

        /**
         * @todo 8、其它状态的频道则需要*授权
         */
        if (!Authorize::isUnion()) {
            // 获取联合授权
            if (is_ajax() || is_pjax()) {
                $this->logcat('error', 'Authority::handler(异步请求需要授权认证)' . __LINE__);

                return $this->response('', 407, 'Asyn Proxy Authentication Required', '异步请求需要授权认证', 'json');
            }

            if (is_get() || Request::isGet()) {
                $result = Authorize::getClient(true)->authorize(
                    $this->appid,
                    $this->secret,
                    Request::url(true),
                    'code',
                    'auth_union',
                    '',
                    $this->lang
                );

                if ($result instanceof Redirect) {
                    $this->logcat('debug', 'Authority::handler(Authorize::dispenser instanceof Redirect)');

                    return $result;
                }

                if (!empty($result) && is_array($result) && isset($result['openid']) && !empty($result['openid'])) {
                    $this->logcat('debug', 'Authority::handler(Wechat UserInfo)' . json_encode($result, JSON_UNESCAPED_UNICODE));

                    $this->onAuthorized($result);
                } else {
                    $this->logcat('error', 'Authority::handler(Request::Param)' . __LINE__ . json_encode(Request::param()));
                }
            }
        }

        if (!Authorize::isUnion()) {
            $this->logcat('error', 'Authority::handler(Proxy Authentication Required)' . __LINE__);

            return $this->response('', 407);
            // return AuthUnion::request(true);
        }

        /**
         * @todo 9、校验授权信息
         */
        $access = $this->channel->getAccess($this->appid, $this->poolid, $channel['channelid'] ?? 404, $this->session->get('union.roleid', 404), $this->debug);

        if (Authorize::isAdmin() || Authorize::isTesting()) {
            $this->logcat('debug', 'Authority::handler(Super Manager has Method[' . Request::method() . '] privileges)');

            return $this->response('', 200);
        }

        if (empty($access)) {
            $this->logcat('error', 'Authority::handler(407 无效的授权信息)' . __LINE__);

            return $this->response('', 407, 'Invalid authorization information', '无效的授权信息');
        }
        if (!isset($access['status']) || $access['status'] != 1) {
            $this->logcat('error', 'Authority::handler(407 授权信息已被禁用)' . __LINE__);

            return $this->response('', 407, 'Authorization information has been disabled', '授权信息已被禁用');
        }

        if (!isset($access['allow']) || $access['allow'] != 1) {
            $this->logcat(
                'debug', 'Authority::handler(402 权限不足)'
                       . ' Channel：' . json_encode($channel, JSON_UNESCAPED_UNICODE)
                       . ' Access：' . json_encode($access, JSON_UNESCAPED_UNICODE)
            );

            return $this->response('', 402, 'Insufficient authority', '权限不足，无法访问该页面');
        }

        if (!isset($access['method']) || (stripos($access['method'], 'ajax') === false && is_ajax())) {
            $this->logcat('error', 'Authority::handler(405 该页面禁止Ajax请求)' . __LINE__);

            return $this->response('', 405, 'Ajax Method Not Allowed', '该页面禁止Ajax请求');
        }

        if (!isset($access['method']) || stripos($access['method'], Request::method()) === false) {
            $this->logcat('error', 'Authority::handler(405 该页面禁止 ' . Request::method() . ' 方法请求)' . __LINE__);

            return $this->response('', 405, Request::method() . ' Method Not Allowed', '该页面禁止' . Request::method() . '请求');
        }

        if (!isset($access['method']) || stripos($access['method'], Request::method()) !== false) {
            $this->logcat('info', 'Authority::handler(Success::' . Request::method() . ')' . Request::url(true));

            return $this->response('', 200);
        }

        $this->logcat('error', 'Authority::handler(406 授权信息异常)' . __LINE__);

        return $this->response('', 406, 'Not Acceptable', '授权信息异常');
    }

    /**
     * 初始化
     *
     */
    protected function initialize(): void {

    }

    /**
     * 获取内部排除项
     *
     * @return string
     */
    private function getInternalIdentifier(): string {
        $identifier = $this->getIdentifier();
        if (!empty($identifier)) {
            return strtolower($identifier);
        }

        return $identifier;
    }

    /**
     * 获取访问标识符
     * 权限标识符（Identifier）推荐使用 resource:action 形式命名，如 email:login
     *
     * @return string
     */
    protected abstract function getIdentifier(): string;

    /**
     * 获取内部排除项
     *
     * @return array
     */
    private function internalIgnore(): array {
        return array_merge(
            $this->getIgnore(), array('/',
                                      'index:*', 'index:index:index', "index.htm", "index.html", "index.php",
                                      'portal:*', 'portal:index:index', "portal.htm", "portal.html", "portal.php",

                                      'captcha:*', '*:captcha:*', 'captcha:index:index',

                                      "favicon.ico", "rotobs.txt",

                                      "404.htm", "404.html",
                                      "502.htm", "502.html"
                              )
        );
    }

    /**
     * 获取排除项
     *
     * @return array
     */
    protected abstract function getIgnore(): array;

    /**
     * 自定义排除算法，排除当前标识符
     *
     * @param string $identifier
     *
     * @return bool
     */
    protected function has_exclude(string $identifier): bool {
        $this->logcat('info', 'Authority::has_exclude(' . $identifier . ')');
        $ignore = $this->internalIgnore();

        return !empty($ignore) && is_array($ignore) && !empty($identifier) && in_array($identifier, $ignore);
    }

    /**
     * 验证频道
     *
     * @param string $identifier
     *
     * @return bool
     */
    protected abstract function has_channel(string $identifier): bool;

    /**
     *验证角色
     *
     * @return bool
     */
    protected abstract function has_role(): bool;

    /**
     * 验证联合授权
     *
     * @return bool
     */
    protected abstract function has_union(): bool;

    /**
     * 验证权限
     *
     * @return bool
     */
    protected abstract function has_permission(): bool;

    /**
     * 请求重定向
     *
     * @param string $url  重定向地址
     * @param int    $code 状态码
     *
     * @return mixed
     */
    protected abstract function redirect(string $url = '', int $code = 302);

    /**
     * OAuth2 获取到用户Openid后，由实现类存储
     *
     * @param string $openid
     *
     * @return bool
     */
    protected abstract function onOpenid(string $openid): bool;

    /**
     * OAuth2 获取到用户信息后，由实现类存储
     *
     * @param $userInfo
     */
    protected abstract function onAuthorized(array $userInfo): void;

    /**
     * 响应输出
     *
     * @param        $data
     * @param int    $code
     * @param string $status
     * @param string $msg
     * @param string $type
     *
     * @return mixed
     */
    protected abstract function response($data, $code = 200, $status = '', $msg = '', $type = 'json');

    /**
     * 自定义实现日志类
     *
     * @param       $level
     * @param       $message
     * @param array $context
     */
    public function logcat($level, $message, array $context = []): void {
    }

}