<?php

declare (strict_types=1);

namespace mark\auth\entity;

final class AppInfo {

    public static $type = array(
        array('id' => 0, 'title' => '网页 App', 'name' => 'WebApp'),
        array('id' => 1, 'title' => '本地 App', 'name' => 'NativeApp'),
        array('id' => 2, 'title' => '混合 App', 'name' => 'HybridApp'),
        array('id' => 3, 'title' => 'IOS App', 'name' => 'IosApp'),
        array('id' => 4, 'title' => 'Android App', 'name' => 'AndroidApp'),
    );

}