# 第 3 章 · 查马：webshell 爱藏在哪、怎么扫

> 原则：先找全，再动手。漏一个后门，前面白干。

## 高危藏身位置（按真实案例排序）

1. **`wp-content/uploads/` 里的 .php**——这个目录本该只有图片附件，出现 PHP 就是马
2. **`wp-content/languages/` 里的异常 .php**——本该只有 .po/.mo 翻译文件（真实案例：`zxvsg.php`，161KB goto 混淆壳）
3. **主题/插件文件末尾被追加**——正常文件结尾多出一行 `eval(...)`（真实案例：主题 `404.php` 末尾 `@eval($_POST['1']);`）
4. **`wp-content/mu-plugins/`**——强制加载目录，马的常客
5. **随机命名文件**——`xkqjwvz2.php` 这种 8 位无意义字符
6. **网站根目录杂散 PHP**、`.user.ini`、被改过的 `.htaccess`

## 方法一：扫描器（推荐）

```bash
python3 sr-scan.py /www/wwwroot/你的域名 --url https://你的域名
```

上面的位置和特征码全内置，【高危】段就是结果。下载见[第 1 章](01-初检-确认被黑.md)。

## 方法二：手动 grep（扫描器跑不了时）

```bash
cd /www/wwwroot/你的域名

# 一句话木马特征
grep -rln --include="*.php" -E "eval\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)" .
grep -rln --include="*.php" -E "assert\s*\(\s*\$_|create_function" .
grep -rln --include="*.php" "preg_replace.*\/e['\"]" .

# base64 藏马（同一文件里同时出现才可疑）
grep -rln --include="*.php" "base64_decode" . | xargs grep -l -E "eval|assert" 2>/dev/null

# goto 混淆（统计单文件 goto 数，≥5 可疑）
grep -rc "goto " --include="*.php" . | awk -F: '$2>=5'

# uploads 里的 PHP
find wp-content/uploads -name "*.php"

# 危险残留（谁都能下载的备份）
ls -la *.sql *.zip *.tar.gz debug.log wp-config.php.bak 2>/dev/null
find . -maxdepth 2 -name "installer.php" -o -name "dup-installer*" 2>/dev/null
```

## 找到之后

**只记录路径，先别删。** 把高危文件清单列全（可能不止一个后门），进下一章统一隔离。漏掉的比误删的麻烦大。

## 下一步

清单齐了 → [第 4 章 清理](04-清理-隔离与删除.md)
