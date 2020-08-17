<?php

declare (strict_types=1);

namespace mark\auth\entity;

final class AuthInfo {

    public static $reserved = array(
        'default'  => array('title' => '默认', 'name' => 'default'),
        'public'   => array('title' => '公开', 'name' => 'public'),
        'proteced' => array('title' => '保护', 'name' => 'proteced'),
        'private'  => array('title' => '私有', 'name' => 'private'),
        'final'    => array('title' => '最终', 'name' => 'final'),
        'static'   => array('title' => '静态', 'name' => 'static'),
        'abstract' => array('title' => '抽象', 'name' => 'abstract'),
        'system'   => array('title' => '系统', 'name' => 'system'),
    );

    public static $modifier = 'modifier';

    public static $default  = 'default';
    public static $public   = 'public';
    public static $proteced = 'proteced';
    public static $private  = 'private';
    public static $final    = 'final';
    public static $static   = 'static';
    public static $abstract = 'abstract';
    public static $system   = 'system';
}