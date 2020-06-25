<?php

declare (strict_types=1);

namespace mark\auth;

use mark\http\Curl;
use mark\src\entity\Subject;

final class SecurityManager {

    private $subject;

    public function __construct() {
        $this->subject = new Subject();
    }

    /**
     * 获取用户主体
     *
     * Subject：主体 （user）（抽象的概念：保存登录后的相关信息）
     *
     * 访问系统的用户，主体可以是用户、程序等，进行认证的都称为主体；
     *
     * @return Subject
     */
    public function getSubject(): Subject {
        return $this->subject;
    }

    /**
     * 身份信息 （username）
     *
     * 是主体（subject）进行身份认证的标识，标识必须具有唯一性，如用户名、手机号、邮箱地址等，一个主体可以有多个身份，但是必须有一个主身份（Primary Principal）（类似于数据库表中的id，保持唯一）。
     */
    public function getPrincipal() {
    }

    /**
     * 凭证信息 （password）
     * 是只有主体自己知道的安全信息，如密码、证书等。
     *
     */
    public function getCredential() {

    }

}