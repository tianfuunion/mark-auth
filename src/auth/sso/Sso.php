<?php

namespace mark\auth\sso;

use mark\auth\Authorize;
use Psr\SimpleCache\CacheInterface;

abstract class Sso {

    /** @var Authorize */
    protected $auth;

    /**
     * @var CacheInterface
     */
    private $cache;

    /**
     * Sso constructor.
     *
     * @param Authorize $auth
     */
    public function __construct(Authorize $auth) {
        $this->auth = $auth;
    }

    /**
     * @param string $scope
     *
     * @return mixed
     */
    abstract public function request($scope = '');

    protected function getCache() {
        if (empty($this->cache)) {
            $this->cache = new class implements CacheInterface {

                function get($key, $default = null) {
                    // TODO: Implement get() method.
                    return $default;
                }

                public function set($key, $value, $ttl = null) {
                    // TODO: Implement set() method.
                }

                public function delete($key) {
                    // TODO: Implement delete() method.
                }

                public function clear() {
                    // TODO: Implement clear() method.
                }

                public function getMultiple($keys, $default = null) {
                    // TODO: Implement getMultiple() method.
                }

                public function setMultiple($values, $ttl = null) {
                    // TODO: Implement setMultiple() method.
                }

                public function deleteMultiple($keys) {
                    // TODO: Implement deleteMultiple() method.
                }

                public function has($key) {
                    return false;
                }

            };
        }

        return $this->cache;
    }

}