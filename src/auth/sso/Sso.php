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

    /**
     * Sso constructor.
     *
     * @param \mark\auth\Authorize $auth
     * @param null                 $level
     */
    public function __construct(Authorize $auth, $level = null) {
        $this->auth = $auth;
        $this->level = $level;
        $this->curl = Curl::getInstance();
    }

    /**
     * @param string $scope
     *
     * @return mixed
     */
    abstract public function request($scope = '');

}