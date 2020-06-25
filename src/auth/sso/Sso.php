<?php

namespace mark\auth\sso;

use mark\auth\Authorize;
use mark\http\Curl;

abstract class Sso {

    /** @var Authorize */
    protected $auth;

    /**@var Curl */
    protected $curl;

    public function __construct(Authorize $auth) {
        $this->auth = $auth;
        $this->curl = Curl::getInstance();
    }

    abstract public function request();

}