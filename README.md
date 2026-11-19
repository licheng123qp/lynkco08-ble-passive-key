# 领克 08 BLE 无感钥匙（Android）

给小米等**未开放 UWB 无感进入**的 Android 手机，补上「靠近解锁 / 远离锁车」。

> ⚠️ **当前状态**：代码与注入链路已跑通，但真实解锁尚未完成车边复测。
> 第一轮实测发现并修复了「冷流未订阅导致命令从未发出」的问题，仍需带车验证。
> 详见 [`docs/05-使用与标定指南.md`](docs/05-使用与标定指南.md) 第六节。

## 这是什么

领克 08 的 UWB 无感进入只对 iPhone 和魅族开放；BLE 蓝牙钥匙虽然可用，
但必须在 APP 里**手动点解锁按钮**。本项目用 BLE RSSI 判断距离，
在靠近 / 远离时自动触发解锁 / 上锁。

核心思路：**不搬钥匙，只在官方 APP 自己的进程里代按那个按钮。**

LSPosed 模块注入 `com.lynkco.customer`，反射调用其内部的
`NearbyControlSend.sendControlCmd(...)`；BLE 扫描与 RSSI 状态机也跑在
官方 APP 进程里，搭它自带的保活便车。凭证、白盒密钥、证书一分不动，
车端看到的始终是官方 APP 本人。

这条路成立，是因为领克 APP 里**本来就有**完整的靠近控制实现
（`NearbyControlImpl.controlApproachUnlock` / `controlWalkAwayLock`、
`BleControlType.DOOR_UNLOCK` / `DOOR_LOCK`），只是没有对小米开放。

## 架构

```
┌─ 自研 APP（配置端）────────┐         ┌─ 官方 APP 进程（dkservice）──────┐
│ MainActivity / Service    │  显式广播 │ BridgeReceiver                  │
│ 参数配置、状态展示、诊断     ├──────────►│ ModuleWatcher  BLE 扫描 + 判定   │
└───────────────────────────┘         │ DkBridge  反射 → sendControlCmd  │
                                      └──────────────┬───────────────────┘
                                                     │ 官方 APP 自身的凭证
                                                ┌────▼────┐
                                                │ 领克 08  │
                                                └─────────┘
```

感知层放在官方 APP 进程里不是偏好，是被系统逼出来的：自研 APP 在 HyperOS 上
会被 Greezer 冻结（`do_freezer_trap`），后台扫描必然停摆；而官方 APP 的
`dkservice` 常驻且持有 `BLUETOOTH_SCAN` / `BLUETOOTH_PRIVILEGED`。

## 免责声明

- 本项目**仅用于个人自有车辆的学习与研究**，请勿用于他人车辆。
- 需要已 root 的 Android 设备与 LSPosed，会修改运行时行为；
  **可能违反车辆厂商或官方 APP 的服务条款**，并可能影响保修。
- 本仓库**不包含**任何厂商 APP、APK、密钥、证书、抓包数据或真实车辆标识。
  所有车辆标识均在运行时从本机读取，文档中的示例值已脱敏。
- 安全相关：BLE RSSI 可被中继放大攻击欺骗，本方案不提供 UWB 级别的安全测距，
  请勿将其作为唯一的车辆安防手段。
- 使用者自行承担全部风险。

## 构建

不依赖 Gradle / Android Studio，用 `aapt2 + javac + d8 + apksigner` 手工构建。

需要准备（放到 `tools/` 下，或修改 `tools/build_apk.py` 顶部的路径常量）：

- JDK 17 → `tools/jdk/`
- Android SDK：`build-tools;34.0.0` 与 `platforms;android-34` → `tools/android-sdk/`

`stubs/` 是 Xposed API 的**编译期占位**（运行期由 LSPosed 框架提供），不打包进 APK。

```bash
python tools/build_apk.py            # 输出 dist/passivekey-debug.apk
```

## 部署

```bash
adb install -r dist/passivekey-debug.apk
# 在 LSPosed 里启用模块，作用域勾选 com.lynkco.customer
adb shell am force-stop com.lynkco.customer
adb shell am start -n com.lynkco.customer/com.geely.lynkco.main.activity.LynkCoEntranceActivity
```

Manifest 里声明了 `xposedscope`，LSPosed 通常会自动生效。

## 到车边怎么验证

按顺序，详见 [`docs/05-使用与标定指南.md`](docs/05-使用与标定指南.md)：

1. 先让官方 APP 连上蓝牙钥匙（「手机钥匙」显示已连接）——**连接由官方 APP 建立**
2. 点我们 APP 的 `STATUS`，确认 `connectStatus=true`
3. 点 `UNLOCK`，看车是否响应
4. 点 `SCAN` → 等 10 秒 → 点 `RESULT`，确认车机实际广播的 MAC

第 4 步是关键判据：如果附近列表里没有车机，说明车机不持续广播，
RSSI 测距方案本身不成立，需要换触发源。

## 目录

```
app/src/com/pkauto/passivekey/
  MainActivity.java          配置界面、参数标定、联调入口
  PassiveKeyService.java     前台服务（只下发配置）
  BridgeClient.java           广播客户端
  BleWatcher.java            独立扫描实现（诊断/参考）
  Prefs.java                  本地配置
  xposed/
    XposedEntry.java         模块入口、dkId 学习
    ModuleWatcher.java        BLE 感知层（跑在官方 APP 进程）
    DkBridge.java             反射调用核心 + Flow 订阅
    BridgeReceiver.java       广播桥服务端
    BridgeServer.java         LocalSocket 通道（已被 SELinux 拒绝，保留作参考）
    ReconDumper.java           结构 dump 与日志
stubs/                        Xposed API 编译期占位
tools/                        构建脚本与逆向辅助工具
docs/
  01-抓包操作手册.md           早期：HCI 日志采集（历史路线）
  02-闸门判定表.md             早期：可行性闸门（历史路线）
  04-架构与工作原理.md         ★ 现在的方案与命令协议
  05-使用与标定指南.md         ★ 操作、标定、故障排查
```

`01` / `02` 是早期「完整自研 BLE 数字钥匙」路线留下的可行性评估记录，
与最终采用的方案不同，保留用于说明「为什么不能自己实现一套数字钥匙」。

## 关键实现细节

- **命令是冷流，必须订阅**：`sendControlCmd` 由 `channelFlow {}` 构造，
  反射直接调用只返回 `ChannelFlowBuilder`，内部 `handleControlCommand`
  要等 `FlowKt.launchIn(flow, scope)` 之后才真正向车端发帧。
  判据是日志里必须出现 `FLOW_SUBSCRIBED`。详见 `docs/04`。
- **广播而非 LocalSocket**：抽象 unix socket 跨 UID 被 SELinux 拒绝；
  显式广播可用且能唤醒后台进程。回执可能被 Greezer 拦截，
  因此命令按单向处理，结果以模块侧日志为准。
- **扫描必须带 `ScanFilter(deviceAddress)`**：Android 对无过滤后台扫描有
  每 30 分钟限流；带过滤的扫描不受限。MAC 取自官方 APP 的 MMKV。
- **驻留按真实时间计**：记录连续满足条件的起始时刻，而非累计采样次数，
  避免广播频率变化导致触发时长漂移。默认解锁 `-75 dBm`、
  上锁 `-82 dBm`、驻留 `4.5 s`，界面可现场热更新。

## 已知限制

- 模块同时注入主进程与 `dkservice`，命令会各执行一次（RKE 幂等，暂未收敛）
- 官方 APP 升级后类名 / 签名可能变化，需重新 dump（`ENABLE_RECON_DUMP`）
- `dkId` 目前以 MMKV 的 `dk_userid` 为初始候选，真值由 hook 学习
- 车机是否持续广播、官方 APP 未连接时的行为，仍待车边确认
