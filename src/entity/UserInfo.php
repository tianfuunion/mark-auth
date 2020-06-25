<?php

declare (strict_types=1);

namespace mark\src\entity;

use think\db\exception\DataNotFoundException;
use think\db\exception\DbException;
use think\db\exception\ModelNotFoundException;
use think\facade\Db;
use think\Model;

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
     * @return array|Model|null
     * @throws DataNotFoundException
     * @throws DbException
     * @throws ModelNotFoundException
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
     * @throws DataNotFoundException
     * @throws DbException
     * @throws ModelNotFoundException
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