# 京麦运营助手0.4.7安装入口

安装入口修订0.4.7-bootstrap.1；完整客户端0.4.7。

# 京麦运营助手（采销版）· ERP安装入口

公开仓库只提供安装引导，不是完整插件市场。7项业务能力、17项官方京麦Skill、统一入口和安装引导共26项，完整包及受保护说明通过本人ERP产品授权领取。版本以正式Release和服务端当前清单为准；本维护源修订不表示已发布新客户端。

## 安装与授权
准备Windows、Node.js 22.15+、Codex CLI、京东网络和本人已登录的京ME/HiOffice。管理员身份与产品使用资格不同。安装入口：
https://github.com/ctzlyj/jingmai-ops-assistant-installer

下载正式Release入口，解压后由Codex执行`node install.mjs`。安装器验权、校验SHA-256并安装完整包；未获准则拒绝该安装，不创建插件目录或登记市场。不要使用`codex plugin marketplace add`直接安装引导仓库。

产品资格维护账号为ERP caotong.888，此信息仅供资格办理，不是普通故障的固定转交流程。七项定制核心仍在服务端逐次验权。插件外独立使用官方CLI不受本插件能力目录限制，也不等于取得受保护产品资格。

## 能力与任务决策
本插件只提供Skill、CLI/API、参数说明和可选校验器，不是当前Codex的任务控制器。当前Codex判断工具、确认方式、执行顺序、批次、重试、恢复及求助，未覆盖任务可发现接口并编写任务局部辅助脚本。插件不另加重复确认、首件门槛、连续错误停机或必须转负责人步骤。

本人ERP授权、店铺身份/权限及接口参数校验继续有效；一个工具报错不等于整个任务必须结束。宿主Codex、公司与平台自身规则不由插件修改。来源资料的流程及命令参数描述该工具的用法，不限制宿主组合其他工具。

## 生图与更新
生图和改图可独立复用本人已配置且适用的API或O2 gpt-image2，不限于SEO维护。JD_LLM_API_KEY与GPT_IMAGE2_API_KEY仅在同一京东网关可作子进程映射。实际图片文件才是成图交付，提示词、dry-run或调用成功不是图片验收。

客户端提供`scripts/jingmai-update.mjs --check`。符合当前automaticFrom及安全检查的兼容补丁按已批准自动方案安装，不是后台强推；只读/不更新、本地改动、运行任务和未决写入时不安装。0.4.0无内置更新器，使用公开入口升级。新代码在新任务加载，不自动重启或恢复业务。说明修订不等于代码已更新，跨机器恢复未验收。

依赖入口是`<插件根>/skills/jingmai-o2-setup/scripts/bootstrap.ps1`；店铺登录工具为`scripts/jingmai-shop-login.mjs`，ERP资格与店铺OAuth是两件事。

## 身份诊断
`node verify.mjs`校验入口文件，`node diagnose-identity.mjs`只读检查本人身份，`node install.mjs --check`查询产品资格，不安装或操作店铺。诊断输出阶段及错误码，不输出身份票据、Cookie或Key。

本入口包含以下身份恢复；版本与发布状态以正式Release及服务端清单为准：
- 本机请求使用直连回环HTTP，不改变远端请求、系统代理或防护配置。IPv4不可达/超时后尝试相同官方候选端口的IPv6；仅连接类故障等待750毫秒再试一轮，受单请求5秒及总时限约束。拒绝访问、异常协议、换票或产品拒绝不盲目重试；不新增18988等猜测端口。
- 安装验权失败时自动附带脱敏环境诊断：Node版本、WSL/远程环境线索，以及Windows已知客户端进程、同用户/会话和候选端口监听线索。不会读取聊天、凭据文件或店铺；进程名称只是线索，不证明已登录，未识别进程也不证明未安装。
- 当前Codex根据具体阶段继续诊断、恢复并回查，不默认要求联系维护人。确需本人验证或权限时说明具体动作；只有产品资格，或已证明必须修改安装器发版且无合规替代的缺陷，才需要维护介入。
- 不自动关闭/重启京ME，不复制登录态或修改受校验入口文件。修复后先诊断、再检查产品资格，成功后继续原安装请求；不自动连接店铺或恢复业务。

| 错误 | 含义 |
| --- | --- |
| ERP_HIOFFICE_UNREACHABLE | 本机身份接口不可达 |
| ERP_HIOFFICE_TIMEOUT | 身份接口超时 |
| ERP_HIOFFICE_ACCESS_DENIED | 本次接口访问被拒绝 |
| ERP_HIOFFICE_PROTOCOL_ERROR | 本机响应不符合协议 |
| ERP_HIOFFICE_TRANSPORT_ERROR | 本机请求运行时异常，不能直接归因为未登录或接口未启动 |
| ERP_TOKEN_EXCHANGE_FAILED | 换票失败 |
| ERP_IDENTITY_REJECTED | 验票服务拒绝票据 |
| ERP_NOT_ALLOWED | 本人产品资格未通过 |
| ERP_AUTH_UNAVAILABLE / ERP_AUTH_TIMEOUT / ERP_AUTH_RESPONSE_INVALID | 授权服务访问、超时或协议问题 |

0.4.1修复过慢京ME身份与错误分类，不代表所有电脑均已修复。官方jdo-cli 0.3.4的OAuth回调监听问题和登录页20001没有已验证的通用修复，不能承诺升级必解决。

JoySpace教程：https://joyspace.jd.com/pages/Fu3S4L71cjvSiyh56hF3 。该页面独立维护，本地文档修改不会自动写入它。
