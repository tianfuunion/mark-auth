<?php

namespace mark\auth\sso;

use mark\auth\Authorize;

abstract class Sso {

    /** @var Authorize */
    protected $auth;

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
    }

    /**
     * @param string $scope
     *
     * @return mixed
     */
    abstract public function request($scope = '');

}