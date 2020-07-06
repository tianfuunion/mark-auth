<?php

    declare (strict_types=1);

    namespace mark\auth\sso\driver;

    use mark\auth\sso\Sso;

    class DingTalk extends Sso
    {

        public function request()
        {
            return false;
        }

    }