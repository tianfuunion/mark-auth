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

}