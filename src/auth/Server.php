<?php

namespace mark\auth;

use mark\http\Curl;
use mark\system\Os;
use mark\src\sso\driver\AliPay;
use mark\src\sso\driver\WeChat;
use mark\src\sso\driver\DingTalk;
use think\facade\Config;

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
     * @author: Mark Zong
     *
     */
    public function request() {
        if (Os::isWeChat() && Config::get('auth.stores.wechat.status', false)) {
            $sso = new WeChat($this->auth);
            return $sso->request();
        }

        if (Os::isAliPay() && Config::get('auth.stores.alipay.status', false)) {
            $sso = new AliPay($this->auth);
            return $sso->request();
        }

        if (Os::isDingTalk() && Config::get('auth.stores.dingtalk.status', false)) {
            $sso = new DingTalk($this->auth);
            return $sso->request();
        }

        return false;
    }

}