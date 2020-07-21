<?php

namespace mark\auth\sso;

interface AuthInterface {

    public function getCode();

    public function getAccessToken();

    public function getUserInfo();

}