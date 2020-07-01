<?php

declare (strict_types=1);

namespace mark\auth\middleware;

use Closure;
use think\App;
use think\Session;
use think\Request;
use think\Response;
use think\facade\Config;
use think\facade\Db;
use think\facade\Log;
use think\db\exception\DataNotFoundException;
use think\db\exception\ModelNotFoundException;
use think\db\exception\DbException;
use mark\auth\entity\AuthInfo;
use mark\auth\AuthUnion;
use mark\auth\Authorize;
use mark\auth\model\Channel;
use mark\response\Responsive;
use app\AuthMiddleware;

/**
 * Class AuthCheck
 *
 * @todo    AppID的有效范围，
 * @package app\ram\middleware
 */
class AuthCheck {

    /** @var App */
    protected $app;
    /** @var Request */
    protected $request;
    /** @var Session */
    protected $session;
    protected $channel;

    public function __construct(App $app, Session $session) {
        $this->app = $app;
        $this->session = $session;
        $this->channel = new Channel(new AuthMiddleware($app, $session));
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

        /** @var Response $response */
        // $response = $next($request);

        // AuthUnion 初始化
        $this->initialize($request);

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
     * @param Request $request
     */
    public function initialize($request) {

    }

    /**
     * 验证频道
     *
     * @return bool
     */
    public function has_channel() {
        try {
            $channel = Db::name('app_channel')
                         ->field(true)
                         ->where('url', '=', rtrim(\think\facade\Request::server('request_uri'), "/"))
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
     */
    public static function has_role() {

    }

    /**
     * 验证联合授权
     */
    public static function has_union() {
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
     */
    public function redirect() {

    }

    /**
     * 1、获取当前频道信息
     * 2、验证当前角色是否拥有该频道的访问权限
     * 3、
     */
    public function verify() {

    }

    public function end(Response $response) {

        // $this->session->save();
    }

}
