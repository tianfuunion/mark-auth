<?php

declare (strict_types=1);

namespace mark\auth\entity;

use Casbin\Enforcer;
use Casbin\Exceptions\CasbinException;

/**
 * Class Subject
 * 管理 API:提供对Casbin策略管理完全支持的基本API。
 *
 * @package mark\auth\entity
 */
final class Subject {

    public function __construct() {

        $e = new Enforcer("path/to/model.conf", "path/to/policy.csv");

        $sub = "alice"; // 想要访问资源的用户。
        $obj = "data1"; // 要访问的资源。
        $act = "read"; // 用户对资源执行的操作。

        try {
            if ($e->enforce($sub, $obj, $act) === true) {
                // 允许alice读取data1
            } else {
                // 拒绝请求，显示错误
            }

            $e->getAllSubjects();

        } catch (CasbinException $e) {
        }
    }

    /**
     * GetAllSubjects 获取当前策略中显示的主题列表。
     */
    public function getAllSubjects() {
    }

    /**
     * 获取当前命名策略中显示的主题列表。
     */
    public function getAllNamedSubjects() {
    }

    /**
     * GetAllObjects 获取当前策略中显示的对象列表。
     */
    public function getAllObjects() {
    }

    /**
     * 获取当前命名策略中显示的对象列表。
     */
    public function getAllNamedObjects() {
    }

    /**
     * 获取当前策略中显示的操作列表。
     */
    public function GetAllActions() {
    }

    /**
     *  获取当前命名策略中显示的操作列表。
     */
    public function GetAllNamedActions() {
    }

    /**
     * 获取当前策略中显示的角色列表。
     */
    public function GetAllRoles() {
    }

    /**
     * 获取当前命名策略中显示的角色列表。
     */
    public function GetAllNamedRoles() {
    }

    /**
     * 获取策略中的所有授权规则。
     */
    public function GetPolicy() {
    }

    /**
     * 获取策略中的所有授权规则，可以指定字段筛选器。
     */
    public function GetFilteredPolicy() {
    }

    /**
     * 获取命名策略中的所有授权规则。
     */
    public function GetNamedPolicy() {
    }

    /**
     * 获取命名策略中的所有授权规则，可以指定字段过滤器。
     */
    public function GetFilteredNamedPolicy() {
    }

    /**
     * 获取策略中的所有角色继承规则。
     */
    public function GetGroupingPolicy() {
    }

    /**获取策略中的所有角色继承规则，可以指定字段筛选器。**/
    public function GetFilteredGroupingPolicy() {
    }

    /**获取策略中的所有角色继承规则。**/
    public function GetNamedGroupingPolicy() {
    }

    /**获取策略中的所有角色继承规则。**/
    public function GetFilteredNamedGroupingPolicy() {
    }

    /**确定是否存在授权规则。**/
    public function HasPolicy() {
    }

    /**确定是否存在命名授权规则。**/
    public function HasNamedPolicy() {

    }

    /**向当前策略添加授权规则。 如果规则已经存在，函数返回false，并且不会添加规则。 否则，函数通过添加新规则并返回true。**/
    public function AddPolicy() {
    }

    /***向当前命名策略添加授权规则。 如果规则已经存在，函数返回false，并且不会添加规则。 否则，函数通过添加新规则并返回true。**/
    public function AddNamedPolicy() {
    }

    /**从当前策略中删除授权规则。**/
    public function RemovePolicy() {
    }

    /**移除当前策略中的授权规则，可以指定字段筛选器。 RemovePolicy 从当前策略中删除授权规则。**/
    public function RemoveFilteredPolicy() {
    }

    /**从当前命名策略中删除授权规则。**/
    public function RemoveNamedPolicy() {
    }

    /**从当前命名策略中移除授权规则，可以指定字段筛选器。**/
    public function RemoveFilteredNamedPolicy() {
    }

    /**确定是否存在角色继承规则。*/
    public function HasGroupingPolicy() {
    }

    /**确定是否存在命名角色继承规则。**/
    public function HasNamedGroupingPolicy() {
    }

    /**向当前策略添加角色继承规则。 如果规则已经存在，函数返回false，并且不会添加规则。 如果规则已经存在，函数返回false，并且不会添加规则。**/
    public function AddGroupingPolicy() {
    }

    /**将命名角色继承规则添加到当前策略。 如果规则已经存在，函数返回false，并且不会添加规则。 否则，函数通过添加新规则并返回true。**/
    public function AddNamedGroupingPolicy() {
    }

    /**从当前策略中删除角色继承规则。**/
    public function RemoveGroupingPolicy() {
    }

    /**从当前策略中移除角色继承规则，可以指定字段筛选器。**/
    public function RemoveFilteredGroupingPolicy() {
    }

    /**从当前命名策略中移除角色继承规则。**/
    public function RemoveNamedGroupingPolicy() {
    }

    /**
     * 从当前命名策略中移除角色继承规则，可以指定字段筛选器。
     */
    public function RemoveFilteredNamedGroupingPolicy() {
    }

    /**
     * 添加自定义函数。
     */
    public function AddFunction() {
    }

}
