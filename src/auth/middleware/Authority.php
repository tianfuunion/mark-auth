<?php

declare (strict_types=1);

namespace mark\auth\middleware;

use think\facade\Config;
use think\facade\Request;

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
abstract class Authority {

    protected $appid  = '';
    protected $poolid = '';
    protected $debug  = false;
    /**
     * @var CacheInterface
     */
    public $cache;

    protected $expire = 1440;

    protected $channel;

    public function __construct() {
        $this->logcat('info', 'Authority::construct(' . Os::getAgent() . ')');
        $this->channel = new Channel($this);
    }

    final public function setAppId($appid): void {
        $this->appid = $appid;
    }

    final public function setPoolId($poolid): void {
        $this->poolid = $poolid;
    }

    final public function setDebug($debug): void {
        $this->debug = $debug;
    }

    final public function setCache(CacheInterface $cache): void {
        $this->cache = $cache;
    }

    final public function setExpire($expire): void {
        $this->expire = $expire;
    }

    /**
     * 处理器
     *
     * @return mixed
     */
    final protected function handler() {
        // 初始化
        $this->initialize();

        /**
         * @todo：2、排除自定义排除项,随后数据来源可从数据库中获取
         */
        $ignore = $this->internalIgnore();
        $identifier = $this->getInternalIdentifier();

        if (empty($identifier)) {
            $this->logcat('error', '无效的频道标识符：标识符' . $identifier);

            return $this->response($identifier, 404, '', '无效的频道标识符', 'json');
        }

        if ($this->has_exclude($identifier)) {
            $this->logcat('info', '自定义排除算法：' . $identifier);

            return $this->response('', 200, '', '', 'json');
        };

        /**
         * @todo 排除自定义标识符：存在Bug，以下情况可能会排除
         * {auth:index:index = index:index}
         */
        if (!empty($ignore) && is_array($ignore)) {
            foreach ($ignore as $key => $item) {
                if (stripos($identifier, $item) !== false) {
                    $this->logcat('info', '排除自定义标识符：' . $identifier . ' = ' . $item);

                    return $this->response('', 200, '', '', 'json');
                    break;
                }
            }
        }

        /**
         * @todo 2、校验标识符，校验频道状态
         */
        $channel = $this->channel->getIdentifier($this->poolid, $this->appid, $identifier, !empty($this->debug) ? 1 : 0);
        if (empty($channel)) {
            $channel = $this->channel->getChannel($this->appid, rtrim(Request::server('document_uri'), "/"), $this->debug);
        }
        $this->logcat('info', 'Authority::handler(Channel Result)' . json_encode($channel, JSON_UNESCAPED_UNICODE));

        /**
         * @todo 3、管理员或测试员 不检查频道状态
         */
        if (Authorize::isAdmin() || Authorize::isTesting()) {
            $this->logcat('debug', 'Authority::Check(Super Manager has Channel privileges)' . $identifier);
        }

        if (empty($channel)) {
            $this->logcat('error', 'Authority::checkChannel(412 无效的频道信息)' . $identifier);

            return $this->response('', 412, 'Invalid Channel information ', '无效的频道信息');
        }
        if ($channel['status'] != 1) {
            $this->logcat('error', 'Authority::checkChannel(501 该频道尚未启用)' . $identifier);

            return $this->response('', 503, 'Channel information not available', '该频道尚未启用');
        }

        /**
         * @todo 4、检查频道是否需要权限检查：公开页面，无需检查
         */
        if ($channel[AuthInfo::$modifier] == AuthInfo::$public) {
            $this->logcat('info', '公开页面，无需检查：' . $identifier);

            return $this->response('', 200);
        }

        /**
         * @todo 5、校验异步请求
         */
        if (!Authorize::isLogin()) {
            if (is_ajax() || is_pjax()) {
                $this->logcat('error', 'Authority::checkChannel(401 身份认证)');

                return $this->response('', 401, 'Ajax Unauthorized', '请求用户的身份认证', 'json');
            }

            if ((is_get() || Request::isGet())) {
                if (!Request::has('code', 'get', true)) {
                    // $response = Authorize::request(true);
                    $url = Config::get('auth.host') . '/auth.php/login/login?callback=' . urlencode(Request::url(true));

                    return $this->response($url, 302, 'Unauthorized', '登录请求');
                } else {
                    // @todo 获取到code之后，请使用本地请求，用户登录数据
                }
            }
            $this->logcat('error', 'Authority::checkChannel(401 身份认证)');

            return $this->response('', 401, 'Unauthorized', '请求用户的身份认证');
        }

        $this->session->set('expiretime', time() + (int)round(abs($this->expire)));

        /**
         * @todo 6、检查频道是否需要权限检查：默认权限，仅登录即可
         */
        if ($channel[AuthInfo::$modifier] == AuthInfo::$default) {
            $this->logcat('info', '默认权限，仅登录即可：' . $identifier);

            return $this->response('', 200);
        }

        /**
         * @todo 7、其它状态的频道则需要*授权
         */
        if (!Authorize::isUnion()) {
            // 获取联合授权
            if (is_ajax() || is_pjax()) {
                $this->logcat('error', 'Authority::checkChannel(异步请求需要授权认证)');

                return $this->response('', 407, 'Asyn Proxy Authentication Required', '异步请求需要授权认证', 'json');
            }

            if (is_get() || Request::isGet()) {
                $url = Config('auth.host') . '/auth.php/oauth2/authorize'
                    . '?appid=' . Config::get('auth.appid')
                    . '&poolid=' . Config::get('auth.poolid')
                    . '&redirect_uri=' . urlencode(Request::url(true))
                    . '&response_type=code'
                    // . '&scope=auth_base'
                    // . '&scope=auth_userinfo'
                    . '&scope=auth_union'
                    . '&access_type=offline'
                    . '&state=' . md5(uniqid((string)time(), true));

                // TODO：临时请求
                return $this->response($url, 302, 'Unauthorized', '登录请求');
                // return Authorize::authentication(Config::get('auth.appid'), Request::url(true));
            }

            $this->logcat('error', 'Authority::checkChannel(Proxy Authentication Required)');

            return $this->response('', 407);
            // return AuthUnion::request(true);
        }

        /**
         * @todo 8、校验授权信息
         */
        $access = $this->channel->getAccess($channel['channelid'], $identifier, $this->session->get('union.roleid', 404));

        if (Authorize::isAdmin() || Authorize::isTesting()) {
            $this->logcat(
                'debug', 'Authority::Check(Super Manager has Method[' . Request::method() . ' ' . __LINE__ . '] privileges)'
            );

            return $this->response('', 200);
        }

        if (empty($access)) {
            $this->logcat('error', 'Authority::checkChannel(407 无效的授权信息)');

            return $this->response('', 407, 'Invalid authorization information', '无效的授权信息');
        }
        if ($access['status'] != 1) {
            $this->logcat('error', 'Authority::checkChannel(407 授权信息已被禁用)');

            return $this->response('', 407, 'Authorization information has been disabled', '授权信息已被禁用');
        }

        if ($access['allow'] != 1) {
            $this->logcat('debug', 'Authority::Check(402 权限不足)');

            return $this->response('', 402, 'Insufficient authority', '权限不足，无法访问该页面');
        }

        if (is_ajax() && stripos($access['method'], 'ajax') === false) {
            $this->logcat('error', 'Authority::checkChannel(405 该页面禁止Ajax请求)');

            return $this->response('', 405, 'Ajax Method Not Allowed', '该页面禁止Ajax请求');
        }

        if (stripos($access['method'], Request::method()) === false) {
            $this->logcat('error', 'Authority::checkChannel(405 该页面禁止 ' . Request::method() . ' 方法请求)');

            return $this->response('', 405, Request::method() . ' Method Not Allowed', '该页面禁止' . Request::method() . '请求');
        }

        if (stripos($access['method'], Request::method()) !== false) {

            $this->logcat('info', 'Authority::Check(Success::' . Request::method() . ')' . Request::url(true));

            return $this->response('', 200);
        }

        $this->logcat('error', 'Authority::checkChannel(406 授权信息异常)');

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
    abstract function getIdentifier(): string;

    /**
     * 获取内部排除项
     *
     * @return array
     */
    private function internalIgnore(): array {
        return array_merge(
            $this->getIgnore(), array('/',
                                      'index:index', 'index:index:index',
                                      'portal:*', 'portal:index',
                                      'captcha', 'captcha:index',

                                      "favicon.ico", "rotobs.txt",

                                      '404', '502')
        );
    }

    /**
     * 获取排除项
     *
     * @return array
     */
    abstract function getIgnore(): array;

    /**
     * 自定义排除算法，排除当前标识符
     *
     * @param string $identifier
     *
     * @return bool
     */
    protected function has_exclude(string $identifier) {
        $this->logcat('info', 'Authority::has_exclude(' . $identifier . ')');

        return false;
    }

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
     * @param string $url  重定向地址
     * @param int    $code 状态码
     *
     */
    abstract function redirect(string $url = '', int $code = 302);

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
    abstract function response($data, $code = 200, $status = '', $msg = '', $type = 'json');

    /**
     * @param       $level
     * @param       $message
     * @param array $context
     */
    public function logcat($level, $message, array $context = []): void {
    }

    /**
     * 1、获取当前频道信息
     * 2、验证当前角色是否拥有该频道的访问权限
     * 3、
     */
    public function verify(): void {

    }

}