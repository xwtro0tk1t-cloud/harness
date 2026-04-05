---
name: supply-chain-audit
description: 多语言供应链投毒检测。支持 python（.pth投毒/setup.py hooks）、npm（postinstall hooks/eval混淆）、go（init() 后门/go:generate）、rust（build.rs）、ruby（extconf.rb）、java（Maven plugin/Gradle exec）、php（composer scripts）。当用户担心供应链安全、想检查依赖投毒、或提到 litellm/ua-parser-js/event-stream 等供应链攻击事件时使用。
allowed-tools: Bash(python3 *), Bash(node *), Bash(npm *), Bash(pip *), Bash(go *), Bash(cargo *), Bash(gem *), Bash(composer *), Bash(find *), Bash(cat *), Bash(ls *), Bash(wc *), Read, Glob, Grep
disable-model-invocation: false
argument-hint: [python|npm|go|rust|ruby|java|php|all] (multiple OK, e.g. "npm python")
---

# Supply Chain Audit — 多语言供应链投毒检测

你正在执行供应链投毒审计。不同语言的包管理器有各自的自动执行入口，攻击者通过这些入口在安装、构建或启动时自动执行恶意代码。

## 参数解析

用户输入: `$ARGUMENTS`

**解析规则**：
- 如果 `$ARGUMENTS` 为空或仅含路径，**询问用户想审计哪些生态系统**，列出支持的选项：`python`、`npm`、`go`、`rust`、`ruby`、`java`、`php`、`all`
- 如果包含生态系统名称，提取所有匹配项并依次执行
- `all` = 检测当前环境中存在的所有生态系统
- 可以组合：`/supply-chain-audit npm python` 同时审计两个

---

## Python 审计模块

**检测目标**：`.pth` 文件投毒 + `setup.py`/`pyproject.toml` 恶意 hooks

### Python Step 1: .pth 文件扫描

```bash
python3 << 'PY_PTH_AUDIT'
import os, sys, site, re, json, hashlib
from datetime import datetime, timezone

CRITICAL_PATTERNS = [
    (r'import\s+.*exec\s*\(', 'import + exec(): 动态代码执行'),
    (r'import\s+.*eval\s*\(', 'import + eval(): 动态表达式求值'),
    (r'import\s+.*\bbase64\b.*decode', 'import + base64 decode: 编码混淆载荷'),
    (r'import\s+.*\bcompile\s*\(', 'import + compile(): 动态编译代码'),
    (r'import\s+.*__import__\s*\(', 'import + __import__(): 动态模块加载'),
    (r'import\s+.*\bsubprocess\b', 'import + subprocess: 执行系统命令'),
    (r'import\s+.*\burllib\b', 'import + urllib: 网络请求'),
    (r'import\s+.*\brequests\b', 'import + requests: 网络请求'),
    (r'import\s+.*\bsocket\b', 'import + socket: 原始网络连接'),
    (r'import\s+.*\bhttp\.client\b', 'import + http.client: HTTP连接'),
    (r'import\s+.*\bctypes\b', 'import + ctypes: 调用C函数'),
]

HIGH_PATTERNS = [
    (r'^import\s+(?![\w.]+\s*$)', 'import行包含非简单模块名（可能执行代码）'),
    (r'import\s+os[;\s]', 'import os: 文件系统/环境变量访问'),
    (r'import\s+sys[;\s]', 'import sys: 解释器操作'),
    (r'import\s+.*;\s*import', 'import链: 多个import用分号连接'),
    (r'import\s+.*\bopen\s*\(', 'import + open(): 文件读写'),
    (r'import\s+.*\bgetenv\b', 'import + getenv: 读取环境变量'),
    (r'import\s+.*\benviron\b', 'import + environ: 访问环境变量字典'),
]

KNOWN_SAFE = {'distutils-precedence.pth','easy-install.pth','setuptools.pth','site.pth'}

SAFE_IMPORT_PATTERNS = [
    r'^import\s+_distutils_hack\s*$',
    r'^import\s+sys;\s*exec\(.*_distutils_hack',
]

def _add_venv_site_packages(prefix, paths):
    if not os.path.isdir(prefix): return
    lib_dir = os.path.join(prefix, 'lib')
    if os.path.isdir(lib_dir):
        for d in os.listdir(lib_dir):
            if d.startswith('python'):
                sp = os.path.join(lib_dir, d, 'site-packages')
                if os.path.isdir(sp): paths.add(sp)
    win_sp = os.path.join(prefix, 'Lib', 'site-packages')
    if os.path.isdir(win_sp): paths.add(win_sp)

def get_site_packages():
    paths = set()
    for p in site.getsitepackages():
        if os.path.isdir(p): paths.add(p)
    user_site = site.getusersitepackages()
    if isinstance(user_site, str) and os.path.isdir(user_site): paths.add(user_site)
    if hasattr(sys, 'real_prefix') or (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix):
        venv_site = os.path.join(sys.prefix, 'lib', f'python{sys.version_info.major}.{sys.version_info.minor}', 'site-packages')
        if os.path.isdir(venv_site): paths.add(venv_site)
    for env_var in ('VIRTUAL_ENV', 'CONDA_PREFIX'):
        val = os.environ.get(env_var, '')
        if val: _add_venv_site_packages(val, paths)
    extra = os.environ.get('PTH_AUDIT_EXTRA_PATH', '')
    if extra and os.path.isdir(extra): paths.add(extra)
    for venv_name in ('.venv', 'venv', 'env', '.env'):
        for base in [os.getcwd(), os.path.expanduser('~')]:
            _add_venv_site_packages(os.path.join(base, venv_name), paths)
    pyenv_root = os.environ.get('PYENV_ROOT', os.path.expanduser('~/.pyenv'))
    versions_dir = os.path.join(pyenv_root, 'versions')
    if os.path.isdir(versions_dir):
        for v in os.listdir(versions_dir):
            _add_venv_site_packages(os.path.join(versions_dir, v), paths)
    return sorted(paths)

def file_sha256(filepath):
    h = hashlib.sha256()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''): h.update(chunk)
    return h.hexdigest()

def is_safe_import(line):
    for pat in SAFE_IMPORT_PATTERNS:
        if re.match(pat, line.strip()): return True
    return False

def scan_pth_file(filepath):
    findings = []
    try:
        with open(filepath, 'r', errors='replace') as f: lines = f.readlines()
    except Exception as e:
        findings.append({'severity':'HIGH','message':f'无法读取文件: {e}','line_num':0,'line_content':'','pattern':'read_error'})
        return findings
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped or stripped.startswith('#'): continue
        if is_safe_import(stripped): continue
        for pat, desc in CRITICAL_PATTERNS:
            if re.search(pat, stripped, re.IGNORECASE):
                findings.append({'severity':'CRITICAL','message':desc,'line_num':i,'line_content':stripped[:200],'pattern':pat})
        for pat, desc in HIGH_PATTERNS:
            if re.search(pat, stripped, re.IGNORECASE):
                if not any(f['line_num']==i and f['severity']=='CRITICAL' for f in findings):
                    findings.append({'severity':'HIGH','message':desc,'line_num':i,'line_content':stripped[:200],'pattern':pat})
    return findings

def main():
    print("=" * 70)
    print("  [PYTHON] .pth File Poisoning Audit")
    print(f"  Python: {sys.executable} ({sys.version.split()[0]})")
    print(f"  Time: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print("=" * 70)
    site_dirs = get_site_packages()
    print(f"\n[*] Scanning {len(site_dirs)} site-packages directories:\n")
    for d in site_dirs: print(f"    {d}")
    all_pth = []
    for d in site_dirs:
        try:
            for f in sorted(os.listdir(d)):
                if f.endswith('.pth'): all_pth.append(os.path.join(d, f))
        except PermissionError: pass
    print(f"\n[*] Found {len(all_pth)} .pth files\n")
    tc = th = ts = 0
    results = []
    for filepath in all_pth:
        fn = os.path.basename(filepath)
        sha = file_sha256(filepath)
        findings = scan_pth_file(filepath)
        wl = fn in KNOWN_SAFE
        has_imp = False
        try:
            with open(filepath,'r',errors='replace') as f:
                for line in f:
                    if line.strip().startswith('import'): has_imp=True; break
        except: pass
        results.append({'file':filepath,'filename':fn,'sha256':sha,'has_import':has_imp,'whitelisted':wl,'findings':findings})
        cc = sum(1 for f in findings if f['severity']=='CRITICAL')
        hc = sum(1 for f in findings if f['severity']=='HIGH')
        tc+=cc; th+=hc
        if cc>0: icon='!!!'
        elif hc>0: icon='!!'
        elif has_imp and not wl: icon='!'
        else: icon='OK'; ts+=1
        line = f"  [{icon:>3}] {fn}"
        if wl and not findings: line+=" (known safe)"
        print(line)
        for f in findings:
            print(f"        [{f['severity']}] Line {f['line_num']}: {f['message']}")
            print(f"               > {f['line_content'][:120]}")
    # Recently modified
    import time
    now = time.time()
    print(f"\n[*] Recently modified .pth files (last 7 days):")
    recent = False
    for fp in all_pth:
        if now - os.path.getmtime(fp) < 7*86400:
            print(f"    [!] {os.path.basename(fp)} - modified {datetime.fromtimestamp(os.path.getmtime(fp)).strftime('%Y-%m-%d %H:%M')}")
            recent = True
    if not recent: print("    [OK] None")
    print(f"\n{'='*70}")
    print(f"  [PYTHON] SUMMARY: {len(all_pth)} files | {tc} CRITICAL | {th} HIGH | {ts} clean")
    if tc>0: print(f"  RESULT: CRITICAL - Possible .pth poisoning detected!")
    elif th>0: print(f"  RESULT: HIGH RISK - Suspicious patterns found")
    else: print(f"  RESULT: CLEAN")
    print("="*70)
    report = {'module':'python-pth','timestamp':datetime.now(timezone.utc).isoformat(),'python':sys.executable,
              'total':len(all_pth),'critical':tc,'high':th,'results':results}
    rdir = os.path.expanduser('~/.claude/audit-reports')
    os.makedirs(rdir, exist_ok=True)
    rp = os.path.join(rdir, f"supply-chain-python-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}.json")
    with open(rp,'w') as f: json.dump(report,f,indent=2,ensure_ascii=False)
    print(f"  Report: {rp}")

main()
PY_PTH_AUDIT
```

### Python Step 2: AI 语义分析

对 Step 1 中 CRITICAL/HIGH 发现的 .pth 文件，用 Read 工具读取完整内容，进行深度分析：
1. 解码 base64/hex 混淆内容，分析真实载荷
2. 溯源确认属于哪个 pip 包（`pip show <pkg>`）
3. 判断是合法行为（setuptools/coverage/editable install）还是真正恶意
4. 评估影响：凭证窃取、网络外发、持久化
5. 标记误报，给出最终判定

---

## npm 审计模块

**检测目标**：install hooks 恶意脚本 + 代码中的 eval/exec 混淆 + 依赖混淆

### npm Step 1: 扫描 install hooks 和可疑代码模式

```bash
python3 << 'NPM_AUDIT'
import os, sys, re, json, hashlib
from datetime import datetime, timezone

DANGEROUS_HOOKS = {'preinstall','postinstall','install','prepare','prepack','prepublish','prepublishOnly'}
INFO_HOOKS = {'prestart','start','poststart','pretest','test','posttest','prebuild','build','postbuild'}

# 代码级恶意模式
CRITICAL_CODE_PATTERNS = [
    (r'eval\s*\(\s*Buffer\.from\s*\(', 'eval(Buffer.from(...)): 编码混淆+执行'),
    (r'eval\s*\(\s*atob\s*\(', 'eval(atob(...)): base64解码+执行'),
    (r'eval\s*\(\s*require\s*\(', 'eval(require(...)): 动态加载+执行'),
    (r'new\s+Function\s*\(.*\bfetch\b', 'new Function() + fetch: 动态构造网络请求'),
    (r'new\s+Function\s*\(.*\bhttp\b', 'new Function() + http: 动态构造网络请求'),
    (r'child_process.*exec\s*\(', 'child_process.exec: 执行系统命令'),
    (r'require\s*\(\s*[\'"]child_process[\'"]\s*\)', 'require child_process: 导入命令执行模块'),
    (r'execSync\s*\(', 'execSync: 同步执行系统命令'),
    (r'spawn\s*\(\s*[\'"](?:bash|sh|cmd|powershell)', 'spawn shell: 启动shell进程'),
    (r'\.readFileSync\s*\(.*(?:\.ssh|\.aws|\.npmrc|\.env|credentials)', '读取敏感凭证文件'),
    (r'process\.env\b.*(?:KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL)', '读取敏感环境变量'),
    (r'https?\.request\s*\(.*(?:method|POST)', 'HTTP POST请求（可能外发数据）'),
    (r'Buffer\.from\s*\(.*,\s*[\'"](?:hex|base64)[\'"]\s*\)\.toString', 'Buffer编码转换（混淆手法）'),
    (r'\\x[0-9a-fA-F]{2}.*\\x[0-9a-fA-F]{2}.*\\x[0-9a-fA-F]{2}', 'Hex转义序列（字符串混淆）'),
    (r'String\.fromCharCode\s*\(.*,.*,.*,', 'fromCharCode批量转换（混淆手法）'),
]

HIGH_CODE_PATTERNS = [
    (r'eval\s*\(', 'eval(): 动态代码执行'),
    (r'new\s+Function\s*\(', 'new Function(): 动态函数构造'),
    (r'require\s*\(\s*[\'"]https?[\'"]\)', 'require http/https: 网络请求模块'),
    (r'require\s*\(\s*[\'"]net[\'"]\)', 'require net: 原始TCP模块'),
    (r'require\s*\(\s*[\'"]dgram[\'"]\)', 'require dgram: UDP模块'),
    (r'require\s*\(\s*[\'"]dns[\'"]\)', 'require dns: DNS模块（可用于隧道）'),
    (r'\.writeFileSync\s*\(.*(?:\.bashrc|\.zshrc|\.profile|crontab)', '写入shell配置文件（持久化）'),
    (r'os\.homedir\s*\(\)', 'os.homedir: 访问用户主目录'),
]

def find_node_modules():
    """查找当前项目和全局的 node_modules"""
    dirs = []
    # 当前项目
    cwd = os.getcwd()
    nm = os.path.join(cwd, 'node_modules')
    if os.path.isdir(nm): dirs.append(('project', nm))
    # 全局
    for gp in [
        os.path.expanduser('~/.npm-global/lib/node_modules'),
        '/usr/local/lib/node_modules',
        '/usr/lib/node_modules',
        os.path.expanduser('~/.nvm/versions/node'),
    ]:
        if gp.endswith('node') and os.path.isdir(gp):
            # nvm: 扫描所有版本
            for v in os.listdir(gp):
                nm_path = os.path.join(gp, v, 'lib', 'node_modules')
                if os.path.isdir(nm_path): dirs.append(('nvm-'+v, nm_path))
        elif os.path.isdir(gp):
            dirs.append(('global', gp))
    # homebrew
    for p in ['/opt/homebrew/lib/node_modules', '/usr/local/lib/node_modules']:
        if os.path.isdir(p) and not any(d[1]==p for d in dirs):
            dirs.append(('global', p))
    return dirs

def scan_package_json(pkg_dir, pkg_name):
    findings = []
    pj_path = os.path.join(pkg_dir, 'package.json')
    if not os.path.isfile(pj_path): return findings
    try:
        with open(pj_path, 'r', errors='replace') as f: pj = json.load(f)
    except: return findings
    scripts = pj.get('scripts', {})
    for hook in DANGEROUS_HOOKS:
        if hook in scripts:
            cmd = scripts[hook]
            severity = 'HIGH'
            detail = f'install hook "{hook}": {cmd[:150]}'
            # 升级为 CRITICAL 的条件
            if any(kw in cmd.lower() for kw in ['curl ','wget ','http://','https://','eval ','base64','powershell','/dev/tcp','|sh','| sh','|bash','| bash']):
                severity = 'CRITICAL'
                detail = f'install hook "{hook}" 包含高危命令: {cmd[:150]}'
            findings.append({'severity':severity,'message':detail,'location':f'{pkg_name}/package.json','hook':hook,'command':cmd[:200]})
    return findings

def scan_js_files(pkg_dir, pkg_name, max_files=20):
    """扫描包中的 JS 文件检测恶意代码模式"""
    findings = []
    count = 0
    for root, dirs, files in os.walk(pkg_dir):
        dirs[:] = [d for d in dirs if d not in ('node_modules','.git','test','tests','__tests__','example','examples','docs')]
        for f in files:
            if not f.endswith(('.js','.cjs','.mjs')): continue
            if count >= max_files: return findings
            count += 1
            fp = os.path.join(root, f)
            try:
                with open(fp, 'r', errors='replace') as fh: content = fh.read(50000)  # 50KB limit
            except: continue
            rel_path = os.path.relpath(fp, pkg_dir)
            for pat, desc in CRITICAL_CODE_PATTERNS:
                matches = list(re.finditer(pat, content))
                for m in matches[:3]:
                    line_num = content[:m.start()].count('\n') + 1
                    context = content[max(0,m.start()-20):m.end()+50].replace('\n',' ')[:150]
                    findings.append({'severity':'CRITICAL','message':desc,'location':f'{pkg_name}/{rel_path}:{line_num}','context':context[:150]})
            for pat, desc in HIGH_CODE_PATTERNS:
                matches = list(re.finditer(pat, content))
                for m in matches[:2]:
                    line_num = content[:m.start()].count('\n') + 1
                    context = content[max(0,m.start()-20):m.end()+50].replace('\n',' ')[:150]
                    findings.append({'severity':'HIGH','message':desc,'location':f'{pkg_name}/{rel_path}:{line_num}','context':context[:150]})
    return findings

def main():
    print("=" * 70)
    print("  [NPM] Supply Chain Audit")
    print(f"  Time: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print("=" * 70)

    nm_dirs = find_node_modules()
    if not nm_dirs:
        print("\n  [*] No node_modules directories found.")
        print("  Tip: Run this from a project directory with node_modules,")
        print("       or set NODE_PATH to scan a specific location.")
        return

    print(f"\n[*] Found {len(nm_dirs)} node_modules locations:\n")
    for label, d in nm_dirs: print(f"    [{label}] {d}")

    total_pkgs = 0
    total_critical = 0
    total_high = 0
    hook_findings = []
    code_findings = []

    for label, nm_path in nm_dirs:
        print(f"\n[*] Scanning {nm_path} ...")
        try:
            entries = sorted(os.listdir(nm_path))
        except PermissionError:
            print(f"    Permission denied"); continue
        for entry in entries:
            pkg_dir = os.path.join(nm_path, entry)
            if entry.startswith('.'): continue
            if entry.startswith('@'):
                # scoped package
                try:
                    for sub in sorted(os.listdir(pkg_dir)):
                        sub_dir = os.path.join(pkg_dir, sub)
                        if os.path.isdir(sub_dir):
                            total_pkgs += 1
                            pkg_name = f'{entry}/{sub}'
                            hf = scan_package_json(sub_dir, pkg_name)
                            hook_findings.extend(hf)
                except PermissionError: pass
            elif os.path.isdir(pkg_dir):
                total_pkgs += 1
                hf = scan_package_json(pkg_dir, entry)
                hook_findings.extend(hf)

    # 对有危险 hook 的包进一步扫描 JS 代码
    dangerous_pkgs = set()
    for f in hook_findings:
        pkg_name = f['location'].split('/package.json')[0]
        dangerous_pkgs.add(pkg_name)

    if dangerous_pkgs:
        print(f"\n[*] Deep scanning {len(dangerous_pkgs)} packages with install hooks...\n")
        for label, nm_path in nm_dirs:
            for pkg_name in dangerous_pkgs:
                pkg_dir = os.path.join(nm_path, pkg_name)
                if os.path.isdir(pkg_dir):
                    cf = scan_js_files(pkg_dir, pkg_name)
                    code_findings.extend(cf)

    all_findings = hook_findings + code_findings
    total_critical = sum(1 for f in all_findings if f['severity']=='CRITICAL')
    total_high = sum(1 for f in all_findings if f['severity']=='HIGH')

    # 输出 hook 发现
    if hook_findings:
        print(f"\n--- Install Hook Findings ({len(hook_findings)}) ---\n")
        for f in sorted(hook_findings, key=lambda x: (0 if x['severity']=='CRITICAL' else 1)):
            print(f"  [{f['severity']:>8}] {f['location']}")
            print(f"             {f['message'][:120]}")
    if code_findings:
        print(f"\n--- Code Pattern Findings ({len(code_findings)}) ---\n")
        for f in sorted(code_findings, key=lambda x: (0 if x['severity']=='CRITICAL' else 1)):
            print(f"  [{f['severity']:>8}] {f['location']}")
            print(f"             {f['message']}")
            if f.get('context'): print(f"             > {f['context'][:120]}")

    print(f"\n{'='*70}")
    print(f"  [NPM] SUMMARY: {total_pkgs} packages | {total_critical} CRITICAL | {total_high} HIGH")
    if total_critical > 0: print(f"  RESULT: CRITICAL")
    elif total_high > 0: print(f"  RESULT: HIGH RISK")
    else: print(f"  RESULT: CLEAN")
    print("="*70)

    report = {'module':'npm','timestamp':datetime.now(timezone.utc).isoformat(),
              'total_packages':total_pkgs,'critical':total_critical,'high':total_high,
              'hook_findings':hook_findings,'code_findings':code_findings}
    rdir = os.path.expanduser('~/.claude/audit-reports')
    os.makedirs(rdir, exist_ok=True)
    rp = os.path.join(rdir, f"supply-chain-npm-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}.json")
    with open(rp,'w') as f: json.dump(report,f,indent=2,ensure_ascii=False)
    print(f"  Report: {rp}")

main()
NPM_AUDIT
```

### npm Step 2: AI 语义分析

对 Step 1 中发现的可疑包，深度分析：
1. 读取 package.json 的 install hook 指向的脚本文件
2. 分析脚本是否包含：网络下载、凭证读取、数据外发、编码混淆
3. 确认包来源是否合法（知名包的 postinstall 通常用于编译 native addon）
4. 常见合法 postinstall：node-gyp rebuild、husky、esbuild、sharp 等
5. 标记误报，给出最终判定

---

## Go 审计模块

**检测目标**：`init()` 函数后门 + `//go:generate` 注入 + `go.mod` replace 劫持

### Go Step 1: 扫描项目依赖

```bash
python3 << 'GO_AUDIT'
import os, sys, re, json
from datetime import datetime, timezone

CRITICAL_PATTERNS = [
    (r'func\s+init\s*\(\s*\)\s*\{[^}]*exec\.Command', 'init() + exec.Command: 启动时执行系统命令'),
    (r'func\s+init\s*\(\s*\)\s*\{[^}]*http\.(Post|Get|Do)', 'init() + HTTP请求: 启动时发起网络连接'),
    (r'func\s+init\s*\(\s*\)\s*\{[^}]*os\.ReadFile.*(?:\.ssh|\.aws|credential)', 'init() + 读取凭证文件'),
    (r'func\s+init\s*\(\s*\)\s*\{[^}]*os\.Getenv.*(?:KEY|SECRET|TOKEN|PASSWORD)', 'init() + 读取敏感环境变量'),
    (r'func\s+init\s*\(\s*\)\s*\{[^}]*net\.Dial', 'init() + net.Dial: 启动时建立网络连接'),
    (r'//go:generate\s+(?:curl|wget|sh|bash|python)', '//go:generate 执行危险命令'),
]

HIGH_PATTERNS = [
    (r'func\s+init\s*\(\s*\)\s*\{[^}]*exec\.Command', 'init() 中调用 exec.Command'),
    (r'func\s+init\s*\(\s*\)\s*\{[^}]*os\.Open', 'init() 中打开文件'),
    (r'//go:generate\s+', '//go:generate 指令'),
    (r'replace\s+\S+\s+=>\s+\S+', 'go.mod replace 指令（可能指向恶意仓库）'),
]

def scan_go_project():
    print("=" * 70)
    print("  [GO] Supply Chain Audit")
    print(f"  Time: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print("=" * 70)

    cwd = os.getcwd()
    gomod = os.path.join(cwd, 'go.mod')
    gopath = os.environ.get('GOPATH', os.path.expanduser('~/go'))
    mod_cache = os.path.join(gopath, 'pkg', 'mod')

    # 检查 go.mod replace 指令
    if os.path.isfile(gomod):
        print(f"\n[*] Checking go.mod: {gomod}\n")
        with open(gomod, 'r') as f:
            content = f.read()
        replaces = re.findall(r'replace\s+(\S+)\s+=>\s+(\S+)', content)
        if replaces:
            for orig, repl in replaces:
                if repl.startswith('..') or repl.startswith('/'):
                    print(f"  [INFO] replace {orig} => {repl} (local path)")
                elif 'github.com' not in repl and 'golang.org' not in repl:
                    print(f"  [HIGH] replace {orig} => {repl} (非标准仓库，需确认)")
                else:
                    print(f"  [ OK ] replace {orig} => {repl}")
        else:
            print("  [OK] No replace directives")
    else:
        print(f"\n[*] No go.mod found in {cwd}")

    # 扫描 vendor/ 或 GOPATH mod cache 中的 init() 和 go:generate
    scan_dirs = []
    vendor = os.path.join(cwd, 'vendor')
    if os.path.isdir(vendor): scan_dirs.append(('vendor', vendor))
    if os.path.isdir(mod_cache): scan_dirs.append(('mod-cache', mod_cache))

    if not scan_dirs:
        print("\n[*] No vendor/ or mod cache found. Run 'go mod vendor' or 'go mod download' first.")
        print("="*70)
        return

    tc = th = total_files = 0
    findings = []
    for label, base in scan_dirs:
        print(f"\n[*] Scanning {label}: {base}")
        for root, dirs, files in os.walk(base):
            dirs[:] = [d for d in dirs if d not in ('.git','testdata','test')]
            for f in files:
                if not f.endswith('.go'): continue
                fp = os.path.join(root, f)
                total_files += 1
                try:
                    with open(fp, 'r', errors='replace') as fh: content = fh.read(100000)
                except: continue
                rel = os.path.relpath(fp, base)
                for pat, desc in CRITICAL_PATTERNS:
                    if re.search(pat, content, re.DOTALL):
                        findings.append({'severity':'CRITICAL','message':desc,'file':rel})
                        tc += 1
                for pat, desc in HIGH_PATTERNS:
                    if re.search(pat, content, re.DOTALL):
                        if not any(ff['file']==rel and ff['severity']=='CRITICAL' for ff in findings):
                            findings.append({'severity':'HIGH','message':desc,'file':rel})
                            th += 1

    for f in sorted(findings, key=lambda x: (0 if x['severity']=='CRITICAL' else 1)):
        print(f"  [{f['severity']:>8}] {f['file']}")
        print(f"             {f['message']}")

    print(f"\n{'='*70}")
    print(f"  [GO] SUMMARY: {total_files} files | {tc} CRITICAL | {th} HIGH")
    if tc>0: print(f"  RESULT: CRITICAL")
    elif th>0: print(f"  RESULT: HIGH RISK")
    else: print(f"  RESULT: CLEAN")
    print("="*70)

scan_go_project()
GO_AUDIT
```

### Go Step 2: AI 语义分析

对发现的可疑 init() 函数和 go:generate 指令，用 Read 工具读取完整代码并分析意图。

---

## Rust 审计模块

**检测目标**：`build.rs` 恶意构建脚本 + proc macro 后门

### Rust Step 1: 扫描 build.rs

```bash
python3 << 'RUST_AUDIT'
import os, sys, re, json
from datetime import datetime, timezone

CRITICAL_PATTERNS = [
    (r'Command::new\s*\(\s*["\'](?:curl|wget|bash|sh|powershell)', 'build.rs 执行危险命令'),
    (r'Command::new.*\.arg.*(?:http://|https://)', 'build.rs 下载远程内容'),
    (r'TcpStream::connect', 'build.rs 建立TCP连接'),
    (r'fs::read_to_string.*(?:\.ssh|\.aws|credential|\.env)', 'build.rs 读取凭证文件'),
    (r'env::var.*(?:KEY|SECRET|TOKEN|PASSWORD)', 'build.rs 读取敏感环境变量'),
    (r'ureq|reqwest|hyper.*get\s*\(', 'build.rs 发起HTTP请求'),
]

HIGH_PATTERNS = [
    (r'Command::new', 'build.rs 执行外部命令'),
    (r'fs::write|fs::create_dir', 'build.rs 写文件'),
    (r'env::var', 'build.rs 读取环境变量'),
]

def main():
    print("=" * 70)
    print("  [RUST] Supply Chain Audit (build.rs)")
    print(f"  Time: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print("=" * 70)

    cargo_home = os.environ.get('CARGO_HOME', os.path.expanduser('~/.cargo'))
    registry = os.path.join(cargo_home, 'registry', 'src')
    cwd_vendor = os.path.join(os.getcwd(), 'vendor')

    scan_dirs = []
    if os.path.isdir(registry):
        for d in os.listdir(registry):
            full = os.path.join(registry, d)
            if os.path.isdir(full): scan_dirs.append(('registry', full))
    if os.path.isdir(cwd_vendor): scan_dirs.append(('vendor', cwd_vendor))

    if not scan_dirs:
        print("\n  [*] No Cargo registry cache or vendor/ found.")
        print("="*70); return

    tc = th = total = 0
    for label, base in scan_dirs:
        print(f"\n[*] Scanning {label}: {base}")
        try: entries = sorted(os.listdir(base))
        except: continue
        for pkg in entries:
            build_rs = os.path.join(base, pkg, 'build.rs')
            if not os.path.isfile(build_rs): continue
            total += 1
            try:
                with open(build_rs, 'r', errors='replace') as f: content = f.read(50000)
            except: continue
            for pat, desc in CRITICAL_PATTERNS:
                if re.search(pat, content):
                    print(f"  [CRITICAL] {pkg}/build.rs: {desc}")
                    tc += 1
            for pat, desc in HIGH_PATTERNS:
                if re.search(pat, content):
                    print(f"  [    HIGH] {pkg}/build.rs: {desc}")
                    th += 1

    print(f"\n{'='*70}")
    print(f"  [RUST] SUMMARY: {total} build.rs files | {tc} CRITICAL | {th} HIGH")
    if tc>0: print(f"  RESULT: CRITICAL")
    elif th>0: print(f"  RESULT: HIGH RISK (most are benign, review needed)")
    else: print(f"  RESULT: CLEAN")
    print("="*70)

main()
RUST_AUDIT
```

---

## Ruby 审计模块

**检测目标**：`extconf.rb` 恶意构建脚本 + gemspec 代码执行

### Ruby Step 1: 扫描 gem 安装目录

```bash
python3 << 'RUBY_AUDIT'
import os, sys, re
from datetime import datetime, timezone

CRITICAL_PATTERNS = [
    (r'system\s*\(\s*["\'](?:curl|wget|bash|sh|powershell)', 'system() 执行危险命令'),
    (r'`(?:curl|wget|bash|sh).*`', '反引号执行危险命令'),
    (r'IO\.popen.*(?:curl|wget|sh|bash)', 'IO.popen 执行危险命令'),
    (r'eval\s*\(\s*Base64\.decode64', 'eval(Base64.decode64(...)): 解码执行'),
    (r'Net::HTTP', 'extconf.rb 中发起HTTP请求'),
    (r'ENV\[.*(?:KEY|SECRET|TOKEN|PASSWORD)', '读取敏感环境变量'),
    (r'File\.read.*(?:\.ssh|\.aws|credential)', '读取凭证文件'),
]

def main():
    print("=" * 70)
    print("  [RUBY] Supply Chain Audit (extconf.rb / gemspec)")
    print(f"  Time: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print("=" * 70)

    gem_dirs = []
    for base in ['/usr/local/lib/ruby/gems', '/usr/lib/ruby/gems',
                 os.path.expanduser('~/.gem/ruby'), os.path.expanduser('~/.rbenv/versions'),
                 '/opt/homebrew/lib/ruby/gems']:
        if os.path.isdir(base):
            for root, dirs, files in os.walk(base):
                if 'gems' in dirs:
                    gem_dirs.append(os.path.join(root, 'gems'))
                dirs[:] = [d for d in dirs if d in ('gems',) or d[0].isdigit()]

    if not gem_dirs:
        print("\n  [*] No Ruby gem directories found.")
        print("="*70); return

    tc = total = 0
    for gd in gem_dirs:
        print(f"\n[*] Scanning: {gd}")
        try: entries = sorted(os.listdir(gd))
        except: continue
        for pkg in entries:
            pkg_dir = os.path.join(gd, pkg)
            for target in ['extconf.rb', 'ext/extconf.rb']:
                fp = os.path.join(pkg_dir, target)
                if not os.path.isfile(fp): continue
                total += 1
                try:
                    with open(fp, 'r', errors='replace') as f: content = f.read(50000)
                except: continue
                for pat, desc in CRITICAL_PATTERNS:
                    if re.search(pat, content, re.IGNORECASE):
                        print(f"  [CRITICAL] {pkg}/{target}: {desc}")
                        tc += 1

    print(f"\n{'='*70}")
    print(f"  [RUBY] SUMMARY: {total} extconf.rb files | {tc} CRITICAL")
    if tc>0: print(f"  RESULT: CRITICAL")
    else: print(f"  RESULT: CLEAN")
    print("="*70)

main()
RUBY_AUDIT
```

---

## Java 审计模块

**检测目标**：Maven plugin exec + Gradle buildscript 命令执行

### Java Step 1: 扫描构建配置

```bash
python3 << 'JAVA_AUDIT'
import os, re, xml.etree.ElementTree as ET
from datetime import datetime, timezone

print("=" * 70)
print("  [JAVA] Supply Chain Audit (Maven/Gradle)")
print(f"  Time: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
print("=" * 70)

cwd = os.getcwd()
tc = th = 0

# Maven: pom.xml
for root, dirs, files in os.walk(cwd):
    dirs[:] = [d for d in dirs if d not in ('.git','node_modules','target','build','vendor')]
    for f in files:
        if f != 'pom.xml': continue
        fp = os.path.join(root, f)
        rel = os.path.relpath(fp, cwd)
        try:
            tree = ET.parse(fp)
            root_el = tree.getroot()
            ns = re.match(r'\{.*\}', root_el.tag)
            ns = ns.group(0) if ns else ''
            for plugin in root_el.iter(f'{ns}plugin'):
                aid = plugin.find(f'{ns}artifactId')
                if aid is not None and aid.text in ('exec-maven-plugin','maven-antrun-plugin','groovy-maven-plugin'):
                    print(f"  [HIGH] {rel}: 使用 {aid.text}（可执行任意代码）")
                    th += 1
                for conf in plugin.iter(f'{ns}configuration'):
                    for exe in conf.iter(f'{ns}executable'):
                        if exe.text and exe.text.strip() in ('bash','sh','curl','wget','python','powershell'):
                            print(f"  [CRITICAL] {rel}: plugin 执行 {exe.text.strip()}")
                            tc += 1
        except: pass

# Gradle: build.gradle / build.gradle.kts
GRADLE_CRITICAL = [
    (r'Runtime\.getRuntime\(\)\.exec', 'Runtime.exec: 执行系统命令'),
    (r'ProcessBuilder\s*\(', 'ProcessBuilder: 执行系统命令'),
    (r'new\s+URL\s*\(.*\)\.text', 'URL.text: 下载远程内容'),
    (r'"curl|"wget|"bash|"sh|"powershell', '执行危险命令'),
]

for root, dirs, files in os.walk(cwd):
    dirs[:] = [d for d in dirs if d not in ('.git','node_modules','target','build','vendor','.gradle')]
    for f in files:
        if f not in ('build.gradle', 'build.gradle.kts', 'settings.gradle', 'settings.gradle.kts'): continue
        fp = os.path.join(root, f)
        rel = os.path.relpath(fp, cwd)
        try:
            with open(fp, 'r', errors='replace') as fh: content = fh.read(100000)
        except: continue
        for pat, desc in GRADLE_CRITICAL:
            if re.search(pat, content):
                print(f"  [CRITICAL] {rel}: {desc}")
                tc += 1

print(f"\n{'='*70}")
print(f"  [JAVA] SUMMARY: {tc} CRITICAL | {th} HIGH")
if tc>0: print(f"  RESULT: CRITICAL")
elif th>0: print(f"  RESULT: HIGH RISK")
else: print(f"  RESULT: CLEAN")
print("="*70)
JAVA_AUDIT
```

---

## PHP 审计模块

**检测目标**：composer.json scripts + autoload.files 注入

### PHP Step 1: 扫描 composer 配置

```bash
python3 << 'PHP_AUDIT'
import os, re, json
from datetime import datetime, timezone

DANGEROUS_SCRIPTS = {'pre-install-cmd','post-install-cmd','pre-update-cmd','post-update-cmd',
                     'post-autoload-dump','pre-autoload-dump','post-root-package-install','post-create-project-cmd'}

print("=" * 70)
print("  [PHP] Supply Chain Audit (Composer)")
print(f"  Time: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
print("=" * 70)

cwd = os.getcwd()
vendor = os.path.join(cwd, 'vendor')
tc = th = total = 0

scan_paths = [cwd]
if os.path.isdir(vendor):
    for entry in os.listdir(vendor):
        ep = os.path.join(vendor, entry)
        if os.path.isdir(ep) and not entry.startswith('.'):
            if entry == 'composer': continue
            for sub in os.listdir(ep):
                sp = os.path.join(ep, sub)
                if os.path.isdir(sp): scan_paths.append(sp)

for pkg_dir in scan_paths:
    cj = os.path.join(pkg_dir, 'composer.json')
    if not os.path.isfile(cj): continue
    total += 1
    rel = os.path.relpath(pkg_dir, cwd) if pkg_dir != cwd else '(project root)'
    try:
        with open(cj,'r',errors='replace') as f: data = json.load(f)
    except: continue
    scripts = data.get('scripts', {})
    for hook in DANGEROUS_SCRIPTS:
        if hook in scripts:
            cmd = scripts[hook]
            if isinstance(cmd, list): cmd = '; '.join(cmd)
            severity = 'HIGH'
            if any(kw in str(cmd).lower() for kw in ['curl','wget','eval','base64','exec','system','passthru','shell_exec']):
                severity = 'CRITICAL'; tc += 1
            else: th += 1
            print(f"  [{severity:>8}] {rel}: {hook} = {str(cmd)[:120]}")
    # autoload.files 检查
    autoload = data.get('autoload', {})
    files = autoload.get('files', [])
    if files and pkg_dir != cwd:
        for af in files:
            afp = os.path.join(pkg_dir, af)
            if os.path.isfile(afp):
                try:
                    with open(afp, 'r', errors='replace') as f: content = f.read(20000)
                    if re.search(r'eval\s*\(|base64_decode|exec\s*\(|system\s*\(|passthru|shell_exec|curl_exec', content):
                        print(f"  [CRITICAL] {rel}: autoload file {af} 包含危险函数")
                        tc += 1
                except: pass

print(f"\n{'='*70}")
print(f"  [PHP] SUMMARY: {total} packages | {tc} CRITICAL | {th} HIGH")
if tc>0: print(f"  RESULT: CRITICAL")
elif th>0: print(f"  RESULT: HIGH RISK")
else: print(f"  RESULT: CLEAN")
print("="*70)
PHP_AUDIT
```

---

## 跨语言通用深度扫描模块

**此模块在所有生态专项扫描之后运行**，对已发现的可疑文件以及所有安装的包代码进行跨语言通用模式检测。Pattern 复用自 skills-audit 的 patterns.py，覆盖 6 大类威胁。

### 通用扫描: 对可疑文件执行全量 pattern 检测

```bash
python3 << 'UNIVERSAL_SCAN'
import os, sys, re, json, base64
from datetime import datetime, timezone

# ============================================================
# 跨语言通用恶意模式库（移植自 skills-audit patterns.py）
# ============================================================

# --- 1. 远程代码执行 (RCE) ---
RCE_PATTERNS = [
    # Shell 管道执行
    (r'curl\s+.*\|\s*(?:bash|sh|zsh|python|perl|ruby)', 'CRITICAL', 'curl pipe to shell: 下载并执行远程脚本'),
    (r'wget\s+.*\|\s*(?:bash|sh|zsh|python|perl|ruby)', 'CRITICAL', 'wget pipe to shell: 下载并执行远程脚本'),
    (r'base64\s+(?:-D|--decode)\s*\|\s*(?:bash|sh|zsh)', 'CRITICAL', 'base64 decode pipe to shell: 混淆后门'),
    (r'\|\s*base64\s+(?:-D|--decode)\s*\|\s*(?:bash|sh|zsh)', 'CRITICAL', 'piped base64 decode+execute'),
    # Python 动态执行
    (r'\beval\s*\(', 'HIGH', 'eval(): 动态代码执行'),
    (r'\bexec\s*\(', 'HIGH', 'exec(): 动态代码执行'),
    (r'__import__\s*\([\'"]os[\'"]', 'MEDIUM', '动态 import os 模块'),
    (r'subprocess\.(?:call|run|Popen).*shell\s*=\s*True', 'HIGH', 'subprocess shell=True: 命令注入风险'),
    (r'os\.system\s*\(', 'HIGH', 'os.system(): 不安全的命令执行'),
    # 反序列化 RCE
    (r'pickle\.loads?\s*\(', 'CRITICAL', 'pickle反序列化: RCE风险'),
    (r'yaml\.(?:load|unsafe_load)\s*\(', 'HIGH', 'yaml.load: 不安全的反序列化'),
    (r'marshal\.loads?\s*\(', 'HIGH', 'marshal反序列化: 代码执行风险'),
    (r'shelve\.open\s*\(', 'MEDIUM', 'shelve.open: pickle反序列化风险'),
    # Node.js
    (r'require\s*\(\s*[\'"]child_process[\'"]\s*\)', 'HIGH', 'require child_process'),
    (r'child_process.*exec\s*\(', 'HIGH', 'child_process.exec: 命令执行'),
    (r'execSync\s*\(', 'HIGH', 'execSync: 同步命令执行'),
    (r'new\s+Function\s*\(', 'HIGH', 'new Function(): 动态函数构造'),
    # Go
    (r'exec\.Command\s*\(', 'MEDIUM', 'exec.Command: 外部命令执行'),
    # Rust
    (r'Command::new\s*\(', 'MEDIUM', 'Command::new: 外部命令执行'),
    # Ruby
    (r'system\s*\(\s*["\']', 'HIGH', 'system(): 命令执行'),
    (r'`[^`]*(?:curl|wget|bash|sh)[^`]*`', 'CRITICAL', '反引号执行危险命令'),
    (r'IO\.popen\s*\(', 'HIGH', 'IO.popen: 命令执行'),
    # PHP
    (r'(?:system|exec|passthru|shell_exec|popen|proc_open)\s*\(', 'HIGH', 'PHP命令执行函数'),
]

# --- 2. 代码混淆 ---
OBFUSCATION_PATTERNS = [
    (r'base64\.(?:b64decode|decodebytes)\s*\(', 'MEDIUM', 'base64解码（可能的混淆）'),
    (r'(?:codecs\.decode|decode)\s*\([^,]+,\s*[\'"]rot[_-]?13[\'"]', 'MEDIUM', 'ROT13解码（混淆）'),
    (r'compile\s*\([^,]+,\s*[\'"]<string>[\'"]', 'HIGH', '动态代码编译'),
    (r'zlib\.decompress\s*\(', 'MEDIUM', 'zlib解压（可能的压缩载荷）'),
    (r'gzip\.decompress\s*\(', 'MEDIUM', 'gzip解压（可能的压缩载荷）'),
    (r'codecs\.decode\s*\(.*[\'"]unicode[_-]escape[\'"]', 'MEDIUM', 'unicode转义解码（混淆）'),
    (r'bytes\.fromhex\s*\(', 'MEDIUM', 'hex解码（可能的混淆）'),
    (r'bytearray\s*\(\s*\[(\s*\d+\s*,){10,}', 'HIGH', '长字节数组（混淆的载荷）'),
    # JS 混淆
    (r'eval\s*\(\s*Buffer\.from\s*\(', 'CRITICAL', 'eval(Buffer.from(...)): 编码混淆+执行'),
    (r'eval\s*\(\s*atob\s*\(', 'CRITICAL', 'eval(atob(...)): base64+执行'),
    (r'Buffer\.from\s*\(.*,\s*[\'"](?:hex|base64)[\'"]\s*\)\.toString', 'HIGH', 'Buffer编码转换（混淆）'),
    (r'String\.fromCharCode\s*\(.*,.*,.*,', 'HIGH', 'fromCharCode批量转换（混淆）'),
    (r'\\x[0-9a-fA-F]{2}.*\\x[0-9a-fA-F]{2}.*\\x[0-9a-fA-F]{2}', 'MEDIUM', 'Hex转义序列（混淆）'),
    (r'\\u[0-9a-fA-F]{4}.*\\u[0-9a-fA-F]{4}.*\\u[0-9a-fA-F]{4}', 'MEDIUM', 'Unicode转义序列（混淆）'),
    (r'chr\s*\(\s*\d+\s*\).*chr\s*\(\s*\d+\s*\)', 'MEDIUM', 'chr()拼接（混淆）'),
]

# --- 3. 网络通信/数据外发 ---
NETWORK_PATTERNS = [
    (r'requests\.(?:get|post|put|delete)\s*\([^)]*(?:data|json|files)\s*=', 'MEDIUM', 'HTTP请求携带数据'),
    (r'urllib\.request\.urlopen\s*\(', 'MEDIUM', 'urllib网络连接'),
    (r'urllib\.request\.urlretrieve\s*\(', 'HIGH', 'urllib下载文件'),
    (r'socket\.(?:socket|create_connection)\s*\(', 'HIGH', '原始socket连接'),
    (r'ftplib\.FTP\s*\(', 'HIGH', 'FTP连接（数据外发风险）'),
    (r'smtplib\.SMTP\s*\(', 'MEDIUM', 'SMTP连接（邮件外发风险）'),
    (r'boto3\.client\s*\([\'"]s3[\'"]', 'MEDIUM', 'AWS S3访问（数据上传风险）'),
    (r'paramiko\.(?:SSHClient|Transport)\s*\(', 'HIGH', 'SSH连接（远程访问）'),
    (r'telnetlib\.Telnet\s*\(', 'HIGH', 'Telnet连接（不安全协议）'),
    (r'xmlrpc\.client\.ServerProxy\s*\(', 'MEDIUM', 'XML-RPC远程调用'),
    # DNS 隧道
    (r'dns\.resolver\.resolve|socket\.getaddrinfo.*TXT', 'HIGH', 'DNS查询（可能的DNS隧道）'),
    # JS网络
    (r'https?\.request\s*\(.*(?:method|POST)', 'HIGH', 'HTTP POST请求（外发数据）'),
    (r'fetch\s*\(.*(?:method|POST)', 'HIGH', 'fetch POST请求（外发数据）'),
    (r'XMLHttpRequest', 'MEDIUM', 'XMLHttpRequest网络请求'),
    (r'WebSocket\s*\(', 'MEDIUM', 'WebSocket连接'),
    # /dev/tcp (bash 网络)
    (r'/dev/tcp/', 'CRITICAL', '/dev/tcp: bash网络连接（反弹shell常用）'),
]

# --- 4. 凭证/密钥访问 ---
CREDENTIAL_PATTERNS = [
    (r'os\.environ\.get\s*\(\s*[\'"].*(?:KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL)[\'"]', 'HIGH', '读取敏感环境变量'),
    (r'os\.environ\s*\[.*(?:KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL)', 'HIGH', '读取敏感环境变量'),
    (r'os\.getenv\s*\(\s*[\'"].*(?:KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL)[\'"]', 'HIGH', '读取敏感环境变量'),
    (r'getpass\.getpass\s*\(', 'MEDIUM', '密码输入提示（凭证收割）'),
    (r'keyring\.get_password\s*\(', 'MEDIUM', '系统密钥链访问'),
    # 敏感文件访问
    (r'open\s*\([^)]*[\'"].*(?:\.ssh|id_rsa|id_ed25519|id_dsa)[\'"]', 'CRITICAL', '读取SSH私钥'),
    (r'open\s*\([^)]*[\'"].*(?:\.aws/credentials|\.aws/config)[\'"]', 'CRITICAL', '读取AWS凭证'),
    (r'open\s*\([^)]*[\'"].*\.kube/config[\'"]', 'CRITICAL', '读取Kubernetes配置'),
    (r'open\s*\([^)]*[\'"].*\.npmrc[\'"]', 'HIGH', '读取npm凭证'),
    (r'open\s*\([^)]*[\'"].*\.pypirc[\'"]', 'HIGH', '读取PyPI凭证'),
    (r'open\s*\([^)]*[\'"].*\.docker/config\.json[\'"]', 'HIGH', '读取Docker凭证'),
    (r'open\s*\([^)]*[\'"].*\.gitconfig[\'"]', 'MEDIUM', '读取git配置'),
    (r'open\s*\([^)]*[\'"].*\.netrc[\'"]', 'HIGH', '读取.netrc凭证'),
    (r'open\s*\([^)]*[\'"].*\.env[\'"]', 'HIGH', '读取.env文件'),
    (r'open\s*\([^)]*[\'"].*GOOGLE_APPLICATION_CREDENTIALS', 'CRITICAL', '读取GCP凭证'),
    # 硬编码密钥
    (r'(?:api[_-]?key|access[_-]?token|secret[_-]?key)\s*=\s*[\'"][a-zA-Z0-9]{20,}[\'"]', 'HIGH', '硬编码API密钥/Token'),
    (r'-----BEGIN\s+(?:RSA|EC|DSA|OPENSSH)?\s*PRIVATE\s+KEY-----', 'CRITICAL', '硬编码私钥'),
    (r'(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}', 'CRITICAL', 'GitHub Token泄露'),
    (r'sk-[A-Za-z0-9]{20,}', 'HIGH', 'OpenAI/Anthropic API Key泄露'),
    (r'AKIA[0-9A-Z]{16}', 'CRITICAL', 'AWS Access Key ID泄露'),
    # JS凭证
    (r'\.readFileSync\s*\(.*(?:\.ssh|\.aws|\.npmrc|\.env|credentials)', 'CRITICAL', 'readFileSync读取凭证'),
    (r'process\.env\b.*(?:KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL)', 'HIGH', 'process.env读取敏感变量'),
]

# --- 5. 持久化/后门 ---
PERSISTENCE_PATTERNS = [
    (r'cron|/etc/crontab|crontab\s+-', 'CRITICAL', 'Cron任务操作（持久化）'),
    (r'\.bashrc|\.bash_profile|\.zshrc|\.profile', 'CRITICAL', 'Shell配置文件修改（持久化）'),
    (r'systemd|/etc/systemd/system', 'CRITICAL', 'Systemd服务操作（持久化）'),
    (r'launchd|/Library/LaunchAgents|/Library/LaunchDaemons|~/Library/LaunchAgents', 'CRITICAL', 'macOS LaunchAgent/Daemon（持久化）'),
    (r'HKEY_|winreg|_winreg', 'HIGH', 'Windows注册表操作（持久化）'),
    (r'/etc/init\.d/', 'HIGH', 'init.d服务操作（持久化）'),
    (r'at\s+\d|schtasks', 'HIGH', '计划任务操作（持久化）'),
    (r'authorized_keys', 'CRITICAL', 'SSH authorized_keys修改（后门）'),
    (r'\.pth\b.*site-packages', 'CRITICAL', 'Python .pth文件操作（启动时投毒）'),
]

# --- 6. 权限提升 ---
PRIVILEGE_PATTERNS = [
    (r'sudo\s+', 'HIGH', 'sudo命令（权限提升）'),
    (r'os\.setuid\s*\(0\)|os\.setgid\s*\(0\)', 'CRITICAL', 'UID/GID设为root'),
    (r'ctypes\..*CDLL.*libc', 'HIGH', '直接调用libc（权限提升风险）'),
    (r'/etc/passwd|/etc/shadow', 'CRITICAL', '密码文件访问'),
    (r'os\.chmod\s*\([^,]+,\s*0o?[47]', 'MEDIUM', '修改文件为可执行权限'),
    (r'setcap|getcap|capabilities', 'HIGH', 'Linux capabilities操作'),
    (r'chown\s+root|chgrp\s+root', 'HIGH', '修改文件所有者为root'),
]

# --- 7. 文件系统破坏 ---
FILESYSTEM_PATTERNS = [
    (r'shutil\.rmtree\s*\(', 'HIGH', '递归删除目录'),
    (r'os\.(?:remove|unlink)\s*\(', 'MEDIUM', '文件删除'),
    (r'pathlib\.Path\s*\([^)]*\)\.(?:unlink|rmdir)', 'MEDIUM', '路径删除'),
    (r'rm\s+-rf\s+/', 'CRITICAL', '递归删除根目录'),
    (r'os\.rmdir\s*\(', 'MEDIUM', '目录删除'),
    (r'truncate\s*\(', 'MEDIUM', '文件截断'),
]

ALL_PATTERNS = (
    RCE_PATTERNS + OBFUSCATION_PATTERNS + NETWORK_PATTERNS +
    CREDENTIAL_PATTERNS + PERSISTENCE_PATTERNS + PRIVILEGE_PATTERNS +
    FILESYSTEM_PATTERNS
)

# ============================================================
# 外部引用提取（URL/IP/域名，含 base64 自动解码）
# ============================================================

def extract_external_refs(text):
    """从文本中提取外部引用，包括自动解码 base64 中的隐藏地址"""
    urls, ips, domains = set(), set(), set()
    texts_to_scan = [text]
    # 尝试解码 base64 字符串
    for m in re.finditer(r'[A-Za-z0-9+/]{20,}={0,2}', text):
        try:
            decoded = base64.b64decode(m.group(0)).decode('utf-8', errors='ignore')
            if any(k in decoded for k in ['http','ftp','.','/']):
                texts_to_scan.append(decoded)
        except: pass
    for t in texts_to_scan:
        for u in re.finditer(r'https?://[^\s<>"\')]+|ftp://[^\s<>"\')]+', t):
            urls.add(u.group(0))
        for ip in re.finditer(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', t):
            parts = ip.group(0).split('.')
            try:
                if all(0 <= int(p) <= 255 for p in parts):
                    ips.add(ip.group(0))
            except: pass
        for d in re.finditer(r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b', t, re.I):
            dom = d.group(0)
            if not dom.endswith(('.py','.js','.ts','.json','.md','.txt','.yml','.yaml','.xml',
                                 '.html','.css','.example','.local','.test','.internal')):
                domains.add(dom)
    return {'urls':sorted(urls),'ips':sorted(ips),'domains':sorted(domains)}

# ============================================================
# 扫描引擎
# ============================================================

def scan_file(filepath, max_size=200000):
    """对单个文件执行全量 pattern 扫描"""
    findings = []
    try:
        size = os.path.getsize(filepath)
        if size > max_size: return findings  # 跳过超大文件
        with open(filepath, 'r', errors='replace') as f:
            content = f.read()
    except: return findings

    for pat, severity, desc in ALL_PATTERNS:
        try:
            for m in re.finditer(pat, content, re.IGNORECASE | re.MULTILINE):
                line_num = content[:m.start()].count('\n') + 1
                context = content[max(0,m.start()-30):m.end()+60].replace('\n',' ')[:150]
                findings.append({
                    'severity': severity,
                    'message': desc,
                    'line': line_num,
                    'match': m.group(0)[:80],
                    'context': context,
                })
        except re.error: continue

    # 提取外部引用
    refs = extract_external_refs(content)
    if refs['urls'] or refs['ips']:
        for u in refs['urls']:
            # 排除常见安全的 URL
            if any(safe in u for safe in ['github.com','pypi.org','npmjs.com','crates.io',
                                           'rubygems.org','maven.org','packagist.org',
                                           'golang.org','googleapis.com','cloudflare.com']):
                continue
            findings.append({'severity':'MEDIUM','message':f'外部URL引用: {u[:100]}',
                           'line':0,'match':u[:80],'context':''})
        for ip in refs['ips']:
            if ip.startswith(('127.','0.','10.','172.16','192.168','::1')): continue
            findings.append({'severity':'HIGH','message':f'外部IP引用: {ip}',
                           'line':0,'match':ip,'context':''})

    return findings

def main():
    print("\n" + "=" * 70)
    print("  [UNIVERSAL] Cross-Language Deep Pattern Scan")
    print(f"  Patterns: {len(ALL_PATTERNS)} rules across 7 categories")
    print(f"  Categories: RCE, Obfuscation, Network, Credentials, Persistence, PrivEsc, FileSystem")
    print(f"  Time: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print("=" * 70)

    # 确定扫描目标：当前工作目录下的包代码
    cwd = os.getcwd()
    targets = []

    # 扫描策略：找到所有包管理器的依赖目录
    scan_roots = []
    # node_modules
    nm = os.path.join(cwd, 'node_modules')
    if os.path.isdir(nm): scan_roots.append(('npm', nm, ('.js','.cjs','.mjs')))
    # Python site-packages（仅扫描 .pth 和 setup.py 之外的可疑文件）
    # vendor/
    vendor = os.path.join(cwd, 'vendor')
    if os.path.isdir(vendor): scan_roots.append(('vendor', vendor, ('.py','.js','.rb','.php','.go')))
    # 如果没有依赖目录，扫描项目源码
    if not scan_roots:
        scan_roots.append(('project', cwd, ('.py','.js','.ts','.go','.rs','.rb','.php','.java','.kt','.groovy')))

    total_files = 0
    total_findings = {'CRITICAL':0, 'HIGH':0, 'MEDIUM':0}
    all_findings = []

    for label, root_dir, extensions in scan_roots:
        print(f"\n[*] Scanning [{label}]: {root_dir}")
        file_count = 0
        for root, dirs, files in os.walk(root_dir):
            dirs[:] = [d for d in dirs if d not in (
                '.git','__pycache__','node_modules','.tox','.mypy_cache',
                '.pytest_cache','dist','build','target','.gradle','.idea',
                '.vscode','coverage','test','tests','__tests__','docs',
                'example','examples','fixtures','vendor'  # 避免递归
            )]
            for f in files:
                if not f.endswith(extensions): continue
                fp = os.path.join(root, f)
                file_count += 1
                findings = scan_file(fp)
                if findings:
                    rel = os.path.relpath(fp, root_dir)
                    for finding in findings:
                        finding['file'] = f"[{label}] {rel}"
                        all_findings.append(finding)
                        sev = finding['severity']
                        if sev in total_findings: total_findings[sev] += 1
        total_files += file_count
        print(f"    Scanned {file_count} files")

    # 输出发现
    if all_findings:
        # 按严重性排序输出
        sorted_findings = sorted(all_findings, key=lambda x: {'CRITICAL':0,'HIGH':1,'MEDIUM':2}.get(x['severity'],3))
        shown = {'CRITICAL':0, 'HIGH':0, 'MEDIUM':0}
        limits = {'CRITICAL':50, 'HIGH':30, 'MEDIUM':10}  # 每级最多显示条数

        print(f"\n--- Universal Pattern Findings ({len(all_findings)} total) ---\n")
        for f in sorted_findings:
            sev = f['severity']
            if shown.get(sev,0) >= limits.get(sev,10):
                continue
            shown[sev] = shown.get(sev,0) + 1
            print(f"  [{sev:>8}] {f['file']}")
            print(f"             {f['message']}")
            if f.get('context'): print(f"             > {f['context'][:120]}")

        for sev in ('CRITICAL','HIGH','MEDIUM'):
            if shown.get(sev,0) < total_findings.get(sev,0):
                print(f"\n  ... and {total_findings[sev]-shown[sev]} more {sev} findings (see JSON report)")

    print(f"\n{'='*70}")
    print(f"  [UNIVERSAL] SUMMARY: {total_files} files | {total_findings['CRITICAL']} CRITICAL | {total_findings['HIGH']} HIGH | {total_findings['MEDIUM']} MEDIUM")
    if total_findings['CRITICAL']>0: print(f"  RESULT: CRITICAL")
    elif total_findings['HIGH']>0: print(f"  RESULT: HIGH RISK")
    elif total_findings['MEDIUM']>0: print(f"  RESULT: MEDIUM RISK")
    else: print(f"  RESULT: CLEAN")
    print("="*70)

    # 保存报告
    report = {
        'module':'universal-deep-scan',
        'timestamp':datetime.now(timezone.utc).isoformat(),
        'total_files':total_files,
        'pattern_count':len(ALL_PATTERNS),
        'findings_count':total_findings,
        'findings':all_findings[:500],  # 限制报告大小
    }
    rdir = os.path.expanduser('~/.claude/audit-reports')
    os.makedirs(rdir, exist_ok=True)
    rp = os.path.join(rdir, f"supply-chain-universal-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}.json")
    with open(rp,'w') as f: json.dump(report,f,indent=2,ensure_ascii=False)
    print(f"  Report: {rp}")

main()
UNIVERSAL_SCAN
```

---

## 通用 AI 分析步骤（所有模块共用）

对所有模块中发现的 CRITICAL/HIGH 级别问题，执行 AI 深度语义分析：

1. **读取可疑文件完整内容**（使用 Read 工具）
2. **解码分析**：base64/hex/Unicode 混淆的真实载荷
3. **溯源**：确认包来源、版本、维护者是否可信
4. **误报过滤**：
   - npm: `node-gyp rebuild`、`husky install`、`esbuild`、`sharp`、`bcrypt` 的 postinstall 是合法的
   - Python: `setuptools`、`coverage`、`editable install` 的 .pth 是合法的
   - Rust: `cc`、`pkg-config`、`bindgen` 等 build.rs 的 Command::new 是合法的
   - Go: `go:generate stringer/protoc/mockgen` 是合法的
   - Java: `maven-compiler-plugin`、`maven-surefire-plugin` 是标准插件
5. **影响评估**：凭证窃取、数据外发、持久化、横向移动
6. **最终判定**：CLEAN / HIGH RISK / CRITICAL

---

## 汇总报告

### 输出格式

```
=== SUPPLY CHAIN AUDIT REPORT ===

Ecosystems scanned: python, npm, go, ...

[PYTHON]  CLEAN     — 4 .pth files, 0 real threats (2 false positives filtered)
[NPM]     HIGH RISK — 523 packages, 3 suspicious install hooks
[GO]      CLEAN     — 0 issues in vendor/

Overall: HIGH RISK
Key findings: ...
Recommendations: ...

Reports saved to ~/.claude/audit-reports/
```

### 防御建议（通用）
- **Python**: `pip install --require-hashes`，CI/CD 中监控 .pth 文件
- **npm**: `npm install --ignore-scripts` + 手动审核需要 hook 的包，使用 `npm audit`
- **Go**: `go mod verify`，审核 `replace` 指令，使用 GONOSUMCHECK 白名单
- **Rust**: `cargo-audit`，审核 build.rs，使用 `cargo-deny`
- **Ruby**: `bundle audit`，审核 extconf.rb
- **Java**: 锁定 plugin 版本，审核 exec-maven-plugin 使用
- **PHP**: `composer audit`，审核 autoload.files

## 注意事项

- 所有扫描纯本地执行，不需要网络访问
- JSON 报告保存在 `~/.claude/audit-reports/supply-chain-{ecosystem}-{timestamp}.json`
- 对于大型项目（>10000 个包），扫描可能需要几十秒
- 每个模块的 AI 分析会过滤已知安全的模式，减少误报
