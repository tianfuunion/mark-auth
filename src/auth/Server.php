<?php

namespace mark\auth;

use mark\http\Curl;
use mark\system\Os;
use mark\auth\sso\driver\AliPay;
use mark\auth\sso\driver\WeChat;
use mark\auth\sso\driver\DingTalk;
use mark\auth\sso\driver\UnionAuth;

class Server {

    /** @var Authorize */
    protected $auth;

    /**@var Curl */
    protected $curl;

    public function __construct(Authorize $auth) {
        $this->auth = $auth;
        $this->curl = Curl::getInstance();
    }

    /**
     * 当前节点为应用节点，并且跨域
     *
     * @return array|bool|mixed 微信用户信息数组
     * @return array|bool|false|mixed|string|\think\response\Redirect
     * @author: Mark Zong
     *
     */
    public function request() {
        if (Os::isWeChat() && Config('auth.stores.wechat.status')) {
            $sso = new WeChat($this->auth);

            return $sso->request();
        }

        if (Os::isAliPay() && Config('auth.stores.alipay.status')) {
            $sso = new AliPay($this->auth);

            return $sso->request();
        }

        if (Os::isDingTalk() && Config('auth.stores.dingtalk.status')) {
            $sso = new DingTalk($this->auth);

            return $sso->request();
        }

        if (is_empty(Config('auth.appid'))) {
            $sso = new UnionAuth($this->auth);

            return $sso->request();
        }

        return false;
    }

}