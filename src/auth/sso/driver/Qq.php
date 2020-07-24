<?php

    declare (strict_types=1);

    namespace mark\auth\sso\driver;

    use mark\auth\sso\Sso;

    class Qq extends Sso
    {

        public function request($scope = '')
        {
            return false;
        }

    }