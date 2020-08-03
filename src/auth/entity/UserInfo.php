<?php

declare (strict_types=1);

namespace mark\auth\entity;

use think\facade\Db;

final class UserInfo {

    private $where = array();
    private $limit = 0;
    private $order = "";

    public function where() {
        $count = func_num_args();
        if ($count === 1) {
            $this->where = array_merge($this->where, func_get_arg($count));
        } elseif ($count === 2) {
            $this->where = array_merge($this->where, array(func_get_arg(0) => func_get_arg(1)));
        } elseif ($count === 3) {
            $this->where = array_merge($this->where, array(func_get_arg(0) => func_get_arg(2)));
        } else {
            $this->where = func_get_args();
        }

        return $this;
    }

    public function order($field, string $order = '') {
        $this->order = $field;

        return $this;
    }

    /**
     * @return array|\think\Model|null
     * @throws \think\db\exception\DataNotFoundException
     * @throws \think\db\exception\DbException
     * @throws \think\db\exception\ModelNotFoundException
     */
    public function find() {
        if (empty($this->where)) {
            return null;
        }

        return Db::name("user")
                 ->withoutField('password')
                 ->where($this->where)
                 ->order("subtime asc")
                 ->find();
    }

    /**
     * @return array
     * @throws \think\db\exception\DataNotFoundException
     * @throws \think\db\exception\DbException
     * @throws \think\db\exception\ModelNotFoundException
     */
    public function select() {
        if (empty($this->where)) {
            return array();
        }

        return Db::name("user")
                 ->withoutField('password')
                 ->where($this->where)
                 ->order("subtime asc")
                 ->select()
                 ->toArray();
    }

    /**
     * @return array
     */
    public function query() {
        return $this->where;
    }

    /**
     * 获取加盐后的安全密码(64位)
     *
     * @param string $password
     * @param string $host
     *
     * @return string
     */
    public static function security_password(string $password, $host = ''): string {
        if (empty($host)) {
            $host = $_SERVER['HTTP_HOST'] ?? $_SERVER['SERVER_NAME'] ?? '';
        }

        $host = parse_host($host);

        // 密码加盐字段
        $salt = strtolower(trim($host));
        $pwd = trim(strval($password));

        $md5_salt = md5($salt);
        $md5_pwd = md5($pwd);
        $hash_pwd = hash("sha256", $pwd);

        $password = hash("sha256", $md5_salt . "_" . $md5_pwd . "_" . $hash_pwd . "_" . hash("sha256", $md5_salt . "_" . $md5_pwd));

        return $password;
    }

}