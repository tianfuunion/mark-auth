<?php

namespace mark\src\sso;

use mark\src\Authorize;
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