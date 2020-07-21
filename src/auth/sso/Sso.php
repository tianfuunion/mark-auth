<?php

namespace mark\auth\sso;

use mark\auth\Authorize;
use mark\http\Curl;

abstract class Sso {

    /** @var Authorize */
    protected $auth;

    /**@var Curl */
    protected $curl;

    protected $level;

    public function __construct(Authorize $auth, $level = null) {
        $this->auth = $auth;
        $this->curl = Curl::getInstance();
        $this->level = $level;
    }

    abstract public function request();

}