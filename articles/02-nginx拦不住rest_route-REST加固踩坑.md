## nginx 拦不住 `?rest_route=`：一次 WordPress REST API 加固踩坑记

### 背景

前阵子网站被黑（过程见上一篇：[《网站被黑挂马两次，我把整个应急过程写出来了》](01-网站被黑挂马两次-应急全过程.md)），清理完之后做加固，其中一项是封掉 WordPress 的用户名枚举。

WordPress 的 REST API 默认暴露用户列表：

```bash
curl https://你的站.com/wp-json/wp/v2/users
# 直接返回所有用户的 id / name / slug
```

攻击者拿到用户名，剩下只要爆破密码。所以这扇门必须关。栈是宝塔 + nginx + PHP（WordPress）。

### 第一方案：nginx 拦截，看起来很美

最直觉的做法是在 nginx 里拦：

```nginx
location ~ /wp-json/wp/v2/users {
    return 403;
}
```

reload 之后测：

```bash
curl https://你的站.com/wp-json/wp/v2/users
# 403 ✓
```

收工。我当时也是这么以为的。

### 翻车：同一个端点，换个写法就绕过去了

隔天复查的时候顺手测了另一种 WordPress 的 REST 路由写法：

```bash
curl "https://你的站.com/?rest_route=/wp/v2/users"
# 200，用户列表原样返回 ✗
```

WordPress 支持两种 REST 访问方式：pretty permalink（`/wp-json/wp/v2/users`）和 query 参数（`?rest_route=/wp/v2/users`）。后者在未开启固定链接的站点上是默认形式，开启了固定链接的站点**照样有效**。

原因很基础，但很容易忘：**nginx 的 `location` 匹配的是 normalized URI（路径部分），根本不包含 query string。**

```
请求: GET /?rest_route=/wp/v2/users
location 看到的: /
```

`location ~ /wp-json/...` 对这个请求连边都碰不到。

当然，nginx 不是完全没办法，可以匹配 `$arg_rest_route` 或用 `if ($query_string ~ ...)`，但 if-in-location 是 nginx 著名的坑，规则复杂了之后维护成本很高，而且本质上是在错误的层做语义判断。

### 正解：在应用层禁掉端点

WordPress 自己就提供了机制——`rest_endpoints` 过滤器，直接在路由注册层面把 users 端点拿掉：

```php
// 主题的 functions.php 末尾
add_filter('rest_endpoints', function ($endpoints) {
    unset($endpoints['/wp/v2/users']);
    unset($endpoints['/wp/v2/users/(?P<id>[\d]+)']);
    return $endpoints;
});
```

效果：

```bash
curl https://你的站.com/wp-json/wp/v2/users
# 404 rest_no_route（PHP 层）

curl "https://你的站.com/?rest_route=/wp/v2/users"
# 404 rest_no_route（PHP 层）
```

无论哪种写法、未来再出什么新写法，路由表里根本没有这个端点，自然 404。

### 最终方案：双保险，各司其职

- **nginx 层**：保留对 `/wp-json/wp/v2/users` 漂亮路径的 403——挡的是批量扫描器，它们绝大多数直接扫标准路径，在边界层拦掉可以省 PHP 起动的开销
- **PHP 层**：`rest_endpoints` 过滤器禁用端点——兜底一切 query 变体和未来的访问形式

同样的思路顺手处理另一个枚举入口 `?author=1`（会 301 暴露用户名），PHP 侧加一个判断直接跳首页，不在 nginx 里碰 query string。

### 验证清单

加固完别只测标准路径，至少测变体：

```bash
curl -o /dev/null -w "%{http_code}\n" https://你的站.com/wp-json/wp/v2/users
curl -o /dev/null -w "%{http_code}\n" "https://你的站.com/?rest_route=/wp/v2/users"
curl -o /dev/null -w "%{http_code}\n" "https://你的站.com/?author=1"
```

期望：403 / 404 / 301（或 404）。

### 两句总结

1. **边界层（nginx）只做粗筛，语义拦截要做在应用层。** 凡是涉及 query 参数、请求方法、Header 语义的拦截，nginx 配置会越来越丑且越来越脆
2. **验证防护要测"变体"不只测"标准写法"。** 攻击者用的从来不是你测的那一种

---

这类踩坑我在陆续整理成一份《宝塔+WordPress 被黑应急与加固 runbook》，包含完整命令和配置，就在[本仓库 runbook 目录](../runbook/README.md)。免费帮清 10 个被黑的站也在进行中，报名见[仓库首页](../README.md)。
