# 交付文档：PURL 组装与来源判定纯函数行为矩阵测试集

## 1. 任务与交付边界

为发布卡点 SBOM 校验所依赖的 purl 组件比对键，补齐其组装与来源判定纯函数的直接单元测试，
钉死当前快照（upstream `40ef5b7`，仓库提交 `6c05c5f`）的现行行为矩阵，防止回归无声破形。

- 交付以**新增测试集为限**。
- **产品代码（`src/**`、`dist/**`）零改动，既有测试文件零改动。**
- 测试针对构建产物 `dist/`（与 `tests/README.md` 既定口径一致），落位 `tests/unit` 单元测试域，
  由既有 jest 运行器按 `testMatch: '**/?(*.)+(spec|test).js'` 自动收录。

## 2. 逐文件改动面登记

| 文件 | 改动性质 | 改动面说明 |
| --- | --- | --- |
| `tests/unit/factories.PackageUrlFactory.spec.js` | **新增（唯一交付物）** | 自命名 spec 单文件，参数化矩阵，覆盖题面十类覆盖点；另含少量覆盖率辅助用例 |
| `tests/unit/factories.PackageUrlFactory.delivery.md` | **新增（本交付文档）** | 非 `.spec/.test.js`，不被 jest 收录，仅作登记留档 |
| `src/factories.ts` | 零改动 | 被测对象，未触碰 |
| `src/_helpers.ts` | 零改动 | 被测对象，未触碰 |
| `tests/unit/versionCompare.spec.js`、`tests/unit/builders.TreeBuilder.spec.js` | 零改动 | 既有测试保持原样且全部通过 |
| 其余 `src/**`、配置、集成测试 | 零改动 | — |

> 工作区实测 `git status --porcelain` 仅出现一个未跟踪条目 `tests/unit/factories.PackageUrlFactory.spec.js`
> （本 `.md` 写于其后）；`dist/`、`node_modules/`、`.c8.cache/`、`.jest.cache/`、`reports/`、
> `tsconfig.tsbuildinfo` 均为既有 `.gitignore` 忽略项，不属于交付改动。

## 3. 矩阵构造路线

1. 先通读 `src/factories.ts`（`PackageUrlFactory.makeFromPackageData` / `makeFromPackageJson`）
   与 `src/_helpers.ts`（两个 matcher、`versionTuple` / `versionCompare`、`tryRemoveSecretsFromUrl` 等），
   沿分支条件反向提取决策点：正则 `i` 标志、`tarball.length > 5` 阈值、`typeof repository === 'object'`、
   `isString` 守卫、版本比较的 `a[i] || 0` 兜底、`try/catch` 的覆盖边界。
2. 对每个决策点取**边界形态**（阈值临界、协议头大小写、短式前缀、片段有无）与
   **退化形态**（缺名称、空/非数字版本段、坏 URL、非字符串字段、空元组）构造参数集。
3. 在仓库外临时目录运行一次性探针脚本，直接 `require` 当前 `dist/` 读出真实返回，
   **以实测读数为准固化断言**，不凭直觉改写现行口径；探针脚本用后即删，不进入交付。
4. 用 `test.each` 参数化承载矩阵，沿用既有 jest 用例形态（`require('@jest/globals')`、CommonJS、
   针对 `dist`、版权头），覆盖路由分支与退化语义两类断言。

## 4. 题面十类覆盖点 → 改动逐条对应

下表每条均在 `factories.PackageUrlFactory.spec.js` 中有同名 `describe` 块与参数化用例。

### 4.1 来源判定（路由分支，3 类）

| # | 覆盖点 | 边界/退化构造输入（实测） | 现行口径断言（实测对齐） | 用例数 |
| --- | --- | --- | --- | --- |
| 1 | 协议头大小写不敏感 | `GIT://`、`GIT+HTTPS://…r.git`、`HTTPS://H/O/R.GIT`、`SsH://`、`SSH://h/r` 等 | 两 matcher 均带 `i` 标志，大小写混合全部命中；命中 vcs 后 resolved **原样拼写**（不折叠大小写）写入 `vcs_url` | 10 |
| 2 | 短式落点 | 短前缀 `git:foo`、`git+file:///x/r`、`ssh:foo`；后缀 `…r.git`、`…r.git#abc`；普通 https；registry URL | `git:`/`git+…:`/`ssh:`/`.git(#\|$)` 落 `vcs_url`；非 registry 且非 vcs 的 https 落 `download_url`；`registry.npmjs.org` 命中 defaultRegistryMatcher → 不带任何 qualifier | 7 |
| 3 | 忽略形态 | `ignore:`/`IGNORE:`、`file:`/`FILE:`、`file:foo.git`（同时命中 vcs）、非字符串 `resolved=12345` | 命中 `^(?:ignore\|file):` 即短路，suppress 全部 qualifier；外层 ignore 判定优先于内层 vcs（`file:foo.git` 仍无 qualifier）；非字符串 resolved 直接跳过。空 qualifiers 经 `PackageURL` 构造后被规整为 `undefined` | 11 |

### 4.2 组装回退链（`makeFromPackageJson`，3 类）

| # | 覆盖点 | 边界/退化构造输入（实测） | 现行口径断言（实测对齐） | 用例数 |
| --- | --- | --- | --- | --- |
| 4 | 压缩包地址退化落回 | 非 registry tarball；registry tarball；长度恰为 5 的 `a.tgz`；长度 6 的 `ab.tgz`；数字 tarball；缺 tarball | 阈值是严格 `length > 5`：5 字符 tarball 退化、落回 repository 分支；非字符串/缺失 tarball 同样落回；非 registry 合格 tarball 落 `download_url`，registry tarball 无 qualifier | 6 |
| 5 | 声明为字符串跳过 | `repository` 为字符串、`null`、`{url:'not a url'}`、`{}`、合法 object | 仅 `typeof === 'object'` 进入分支：字符串/null 被跳过；object 内 `new URL` 抛错被 `catch{}` 吞掉 → 无 qualifier；合法 object 落 `vcs_url` | 5 |
| 6 | 目录编进片段 | `directory:'packages/beta'`、`directory:42`、缺 directory | 字符串 directory 赋给 `url.hash`，渲染为 `#packages%2Fbeta` 编进 `vcs_url`；非字符串 directory 被 `isString` 拦截不追加 hash；缺省时 URL 原样 | 3 |

### 4.3 退化输入语义（3 类）

| # | 覆盖点 | 边界/退化构造输入（实测） | 现行口径断言（实测对齐） | 用例数 |
| --- | --- | --- | --- | --- |
| 7 | 缺名称抛错 | `data=undefined`、`data=null`、`{name:undefined}`、packageJson 无 `name`；以及 `name:''` | 名称访问 / `name.startsWith` 位于 `try` 之外 → 抛 `TypeError` 并向上传播（不转 `undefined`）；空名称能过访问但被 `PackageURL` 以 PurlError 拒绝，该错误在 `try/catch` 内 → 返回 `undefined` | 6 |
| 8 | 空版本元组 | `versionTuple('')`、`('1..3')`、`('1.2.3')`；factory 的 `version=undefined/null/42/'1.2.3'`；packageJson `version=7` | `''`→冻结的 `[0]`，`'1..3'`→`[1,0,3]`，结果均 `Object.freeze`；`makeFromPackageData` 经 `isString` 守卫把非字符串版本降为 `undefined` → purl 无 `@version`；**不对称点**：`makeFromPackageJson` 无此守卫，数字版本直传 `PackageURL` 被拒 → `undefined` | 8 |
| 9 | 非数字版本段比较 | `[]`/`[]`、`[]`/`[1]`、`[1]`/`[]`、`versionTuple('1.x.3')`、`('1.x')`、`('1.2.x')`、`[0]`/`[0,0,0]`、`[0]`/`[0,0,1]` | 非数字段 `Number('x')→NaN`，比较中经 `a[i] || 0` 按 0 处理：NaN 对齐 0/缺位判等，NaN 对齐正数判负；缺位补 0；空元组互比为 0、对非空判负 | 9 |

### 4.4 来源净化（1 类）

| # | 覆盖点 | 边界/退化构造输入（实测） | 现行口径断言（实测对齐） | 用例数 |
| --- | --- | --- | --- | --- |
| 10 | 净化函数解析失败原样返回 | `'not a url'`、`''`、`'::::'`（均使 `new URL` 抛 `TypeError`）；另含成功侧对照 | 解析失败走 `catch` → **入参原样返回**（同一字符串）；成功侧仅清空 `password`、保留 `user`；无凭据 URL 不变 | 5 |

**十类覆盖点参数化用例合计：70 个，逐类全部通过（70/70）。**

### 4.5 覆盖率辅助用例（不计入十类，仅为满足两文件函数覆盖门槛）

为让 `dist/_helpers.js` 的其余导出函数也被执行，补充 14 个现行行为钉断用例：
`isString`(4)、`iterableMap`/`iterableFilter`/`setDifference`(4)、`loadJsonFile`/`writeAllSync`(4，
仅用 `node:fs`/`node:os` 临时目录)、`normalizePackageManifest`(2)。
新增 spec 用例总数 **84 个，全部通过（84/84）**。

## 5. 验收命令与实测读数留档

### 5.1 验收命令（题面指定，零外部依赖、快照内可复现）

```shell
npm run build
npx c8 --reporter=text --include=dist/factories.js --include=dist/_helpers.js npx jest tests/unit
```

### 5.2 jest 通过读数（实测）

```
PASS tests/unit/builders.TreeBuilder.spec.js
PASS tests/unit/factories.PackageUrlFactory.spec.js
PASS tests/unit/versionCompare.spec.js

Test Suites: 3 passed, 3 total
Tests:       100 passed, 100 total   # 既有 16（保持通过） + 新增 84
Snapshots:   0 total
```

零失败。新增 spec 单独运行：`Tests: 84 passed, 84 total`。

### 5.3 c8 覆盖率读数（实测，text reporter）

```
File          | % Stmts | % Branch | % Funcs | % Lines | Uncovered Line #s
--------------|---------|----------|---------|---------|-------------------
All files     |   92.34 |    90.56 |    92.3 |   92.34 |
 _helpers.js  |   91.66 |    88.46 |    90.9  |   91.66 | 46-50,93-96
 factories.js |   93.18 |    92.59 |     100  |   93.18 | 30-31,51-54
```

- `dist/factories.js` 函数覆盖率 **100%** ≥ 90% ✅
- `dist/_helpers.js` 函数覆盖率 **90.9%** ≥ 90% ✅
- 未覆盖行均为难以在纯单测内构造的分支：`writeAllSync` 的 `EAGAIN` 重试循环（46-50）、
  `setDifference` 的运行时降级 fallback（93-96）、`makeFromPackageData` 的顶层 `catch` 兜底（30-31、51-54）。

### 5.4 十类覆盖点逐类通过读数（jest `--json` 实测）

```
10/10  source routing — protocol header case-insensitive
 7/7   source routing — short-form matcher landing spots
11/11  source routing — ignore forms
 6/6   makeFromPackageJson fallback chain — tarball degradation
 5/5   makeFromPackageJson fallback chain — string repository skipped
 3/3   makeFromPackageJson fallback chain — directory encoded as fragment
 6/6   degraded input — missing name throws
 8/8   degraded input — empty version tuple semantics
 9/9   degraded input — non-numeric segment comparison
 5/5   tryRemoveSecretsFromUrl（含解析失败原样返回）
（以上十类合计 70/70；另覆盖率辅助 14/14；spec 总计 84/84）
```

## 6. 可复现性与依赖边界

- 构造全程在快照环境内完成：测试仅依赖 `@jest/globals`、node 内置模块
  （`node:fs`、`node:os`、`node:path`）与当前 `dist/` 产物，无任何网络/外部服务/新增依赖。
- 临时文件用例在 OS 临时目录自建自删，不污染仓库与 `tests/_data`。
- 新 spec 通过项目 `tools/code-style` 的 eslint 校验（`eslint <spec>` 无报错）。
- 断言来源均可回溯：每条断言先由仓库外一次性探针在当前 `dist/` 实测读出，再原样固化，
  探针脚本未纳入交付，删除后不影响复现（按 §5.1 命令即可重放全部读数）。
