package com.pkauto.passivekey.xposed;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 数字钥匙桥：在官方 APP 进程内反射调用其内部 API。
 *
 * 设计原则：
 *  - 绝不搬运凭证，所有调用都发生在官方 APP 自己的进程与身份下；
 *  - 所有反射入口都做多级降级（优先高层语义 API，失败退到底层发送）；
 *  - 任何异常只记录、不抛出，避免影响官方 APP 自身运行。
 */
final class DkBridge {

    static final String CLS_NEARBY_SEND =
            "com.geely.snc.basevehicle.control.ble.NearbyControlSend";
    static final String CLS_NEARBY_IMPL =
            "com.geely.snc.basevehicle.control.impl.NearbyControlImpl";
    static final String CLS_BLE_CONTROL_TYPE =
            "com.geely.snc.basevehicle.control.request.BleControlType";
    static final String CLS_CMD_CHANNEL =
            "com.geely.snc.basevehicle.control.request.CmdChannel";
    static final String CLS_CMD_ACTION =
            "com.geely.snc.basevehicle.control.request.CmdAction";
    static final String CLS_BLE_EVENT =
            "com.geely.snc.basevehicle.control.ble.BleEventHandler";
    static final String CLS_CONN_SERVICE =
            "com.geely.snc.basevehicle.connection.IVehDkConnService";

    /** dkId 候选池：MMKV 预载 + hook 学习 + 主 APP 下发 */
    private static final List<String> CANDIDATES =
            java.util.Collections.synchronizedList(new ArrayList<String>());

    /** 学习到的最高优先级 dkId（来自真实调用，可信度最高） */
    private static volatile String learnedDkId;

    /** 已知的通道候选，按顺序尝试 */
    private static final String[] CHANNEL_CANDIDATES = {"DK20", "DK15"};

    /** 车机 BLE MAC（感知层用） */
    private static volatile String vehicleMac;

    private static ClassLoader cl;
    private static final Map<String, Class<?>> CLS_CACHE =
            new ConcurrentHashMap<String, Class<?>>();

    private DkBridge() {
    }

    static void init(ClassLoader classLoader) {
        cl = classLoader;
    }

    // ==================== dkId 候选管理 ====================

    /** 从真实调用学到的 dkId，优先级最高 */
    static void learnDkId(String v) {
        if (!plausible(v)) {
            return;
        }
        if (v.equals(learnedDkId)) {
            return;
        }
        learnedDkId = v;
        ReconDumper.log("学到 dkId = " + mask(v));
        ReconDumper.record("LEARN dkId=" + v);
    }

    /** 添加候选（MMKV / 配置来源），已存在则忽略 */
    static void addCandidate(String v) {
        if (!plausible(v)) {
            return;
        }
        synchronized (CANDIDATES) {
            if (CANDIDATES.contains(v)) {
                return;
            }
            CANDIDATES.add(v);
        }
        ReconDumper.log("候选 dkId + " + mask(v));
    }

    private static boolean plausible(String v) {
        if (v == null) {
            return false;
        }
        int n = v.length();
        if (n < 8 || n > 128) {
            return false;
        }
        if (v.contains("/") || v.contains(" ") || v.contains("\n")) {
            return false;
        }
        return true;
    }

    /** 按优先级返回待尝试的 dkId 列表 */
    static List<String> dkIdPool() {
        List<String> out = new ArrayList<String>();
        if (learnedDkId != null) {
            out.add(learnedDkId);
        }
        synchronized (CANDIDATES) {
            for (String c : CANDIDATES) {
                if (!out.contains(c)) {
                    out.add(c);
                }
            }
        }
        return out;
    }

    static String getDkId() {
        List<String> p = dkIdPool();
        return p.isEmpty() ? null : p.get(0);
    }

    static String getVehicleMac() {
        return vehicleMac;
    }

    /**
     * 从 MMKV(ble_sdk) 读取基础配置。
     * MMKV 对短字符串是明文顺序存储，直接按字节扫描即可。
     */
    static void loadFromMmkv(java.io.File appFilesDir) {
        try {
            java.io.File f = new java.io.File(appFilesDir, "mmkv/ble_sdk");
            if (!f.exists()) {
                ReconDumper.log("MMKV ble_sdk 不存在: " + f);
                return;
            }
            byte[] d = readAll(f);
            String txt = new String(d, "ISO-8859-1");
            String uid = scanAfter(txt, "dk_userid", "[0-9]{6,32}");
            if (uid != null) {
                addCandidate(uid);
                ReconDumper.log("MMKV dk_userid = " + mask(uid));
            }
            String mac = scanAfter(txt, "dk_connected_mac",
                    "[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}");
            if (mac != null) {
                vehicleMac = mac.toUpperCase();
                ReconDumper.log("MMKV 车机 MAC = " + vehicleMac);
            }
            String vin = scanAfter(txt, "dk_vin", "[A-Z0-9]{11,20}");
            if (vin != null) {
                ReconDumper.log("MMKV VIN = " + vin);
            }
        } catch (Throwable t) {
            ReconDumper.log("读取 MMKV 失败: " + t);
        }
    }

    private static byte[] readAll(java.io.File f) throws java.io.IOException {
        java.io.FileInputStream in = new java.io.FileInputStream(f);
        try {
            byte[] buf = new byte[(int) f.length()];
            int off = 0;
            while (off < buf.length) {
                int n = in.read(buf, off, buf.length - off);
                if (n <= 0) {
                    break;
                }
                off += n;
            }
            return buf;
        } finally {
            try {
                in.close();
            } catch (Throwable ignored) {
            }
        }
    }

    /** 在 key 之后一段范围内用正则找值 */
    private static String scanAfter(String txt, String key, String valueRegex) {
        int p = txt.indexOf(key);
        if (p < 0) {
            return null;
        }
        int end = Math.min(txt.length(), p + key.length() + 160);
        String seg = txt.substring(p + key.length(), end);
        java.util.regex.Matcher m =
                java.util.regex.Pattern.compile(valueRegex).matcher(seg);
        return m.find() ? m.group() : null;
    }

    static String mask(String s) {
        if (s == null) {
            return "null";
        }
        if (s.length() <= 8) {
            return s;
        }
        return s.substring(0, 4) + "***" + s.substring(s.length() - 4);
    }

    // ==================== 反射工具 ====================

    static Class<?> cls(String name) {
        Class<?> c = CLS_CACHE.get(name);
        if (c != null) {
            return c;
        }
        try {
            c = Class.forName(name, true, cl);
            CLS_CACHE.put(name, c);
            return c;
        } catch (Throwable t) {
            return null;
        }
    }

    /** 从枚举类按名字取常量 */
    static Object enumConst(String clsName, String constName) {
        Class<?> c = cls(clsName);
        if (c == null) {
            return null;
        }
        try {
            for (Object o : c.getEnumConstants()) {
                if (o != null && constName.equals(o.toString())) {
                    return o;
                }
            }
        } catch (Throwable t) {
            ReconDumper.log("取枚举失败 " + clsName + "." + constName + ": " + t);
        }
        return null;
    }

    /** 列出枚举全部常量名，用于日志与降级 */
    static List<String> enumNames(String clsName) {
        List<String> out = new ArrayList<String>();
        Class<?> c = cls(clsName);
        if (c == null) {
            return out;
        }
        try {
            for (Object o : c.getEnumConstants()) {
                if (o != null) {
                    out.add(o.toString());
                }
            }
        } catch (Throwable ignored) {
        }
        return out;
    }

    /** 取静态字段值（Kotlin object 的 INSTANCE） */
    static Object staticField(String clsName, String field) {
        Class<?> c = cls(clsName);
        if (c == null) {
            return null;
        }
        try {
            Field f = c.getDeclaredField(field);
            f.setAccessible(true);
            return f.get(null);
        } catch (Throwable t) {
            return null;
        }
    }

    /**
     * 构造 kotlin.coroutines.Continuation。
     *
     * 协程上下文优先用 Dispatchers（保证内部 withContext/delay 可执行），
     * 取不到时退回 EmptyCoroutineContext。
     */
    static Object newContinuation(final String tag) {
        Object ctx = coroutineContext();
        Class<?> contCls = cls("kotlin.coroutines.Continuation");
        if (contCls == null) {
            ReconDumper.log("找不到 Continuation 接口");
            return null;
        }
        final Object context = ctx;
        try {
            return Proxy.newProxyInstance(cl, new Class<?>[]{contCls},
                    new InvocationHandler() {
                        @Override
                        public Object invoke(Object proxy, Method m, Object[] args) {
                            String n = m.getName();
                            if ("getContext".equals(n)) {
                                return context;
                            }
                            if ("resumeWith".equals(n)) {
                                Object r = args != null && args.length > 0 ? args[0] : null;
                                ReconDumper.record("CORO_RESUME [" + tag + "] "
                                        + briefResult(r));
                                return null;
                            }
                            if ("toString".equals(n)) {
                                return "PKContinuation(" + tag + ")";
                            }
                            if ("hashCode".equals(n)) {
                                return System.identityHashCode(proxy);
                            }
                            if ("equals".equals(n)) {
                                return proxy == (args != null && args.length > 0 ? args[0] : null);
                            }
                            return null;
                        }
                    });
        } catch (Throwable t) {
            ReconDumper.log("构造 Continuation 失败: " + t);
            return null;
        }
    }

    private static String briefResult(Object r) {
        if (r == null) {
            return "null";
        }
        try {
            // kotlin.Result 是 value class，运行时可能被装箱
            String s = String.valueOf(r);
            return s.length() > 200 ? s.substring(0, 200) : s;
        } catch (Throwable t) {
            return "<" + r.getClass().getSimpleName() + ">";
        }
    }

    private static Object coroutineContext() {
        String[][] getters = {
                {"kotlinx.coroutines.Dispatchers", "getIO"},
                {"kotlinx.coroutines.Dispatchers", "getDefault"},
        };
        for (String[] g : getters) {
            Class<?> c = cls(g[0]);
            if (c == null) {
                continue;
            }
            try {
                Object inst = c;
                Method m;
                try {
                    m = c.getMethod(g[1]);
                    return m.invoke(inst);
                } catch (NoSuchMethodException e) {
                    // Kotlin object：INSTANCE.getXxx()
                    Field f = c.getDeclaredField("INSTANCE");
                    f.setAccessible(true);
                    Object obj = f.get(null);
                    m = c.getMethod(g[1]);
                    return m.invoke(obj);
                }
            } catch (Throwable ignored) {
            }
        }
        try {
            Class<?> c = cls("kotlin.coroutines.EmptyCoroutineContext");
            if (c != null) {
                Field f = c.getDeclaredField("INSTANCE");
                f.setAccessible(true);
                return f.get(null);
            }
        } catch (Throwable ignored) {
        }
        return null;
    }

    // ==================== 状态查询 ====================

    /** 当前 BLE 连接状态（不依赖 dkId 也能查） */
    static String connectionStatus() {
        Object ev = staticField(CLS_BLE_EVENT, "INSTANCE");
        if (ev != null) {
            try {
                Method m = ev.getClass().getMethod("getConnectStatus");
                Object r = m.invoke(ev);
                return "BleEventHandler.connectStatus=" + r;
            } catch (Throwable ignored) {
            }
        }
        return "无法获取连接状态";
    }

    // ==================== 核心：解锁 / 上锁 ====================

    /**
     * 通过 NearbyControlSend 发送 BLE 控制命令。
     *
     * sendControlCmd(String dkId, BleControlType type, CmdChannel channel,
     *                int seq, byte[] payload, Continuation cont)
     */
    static String sendBleCommand(String typeName) {
        Object sender = staticField(CLS_NEARBY_SEND, "INSTANCE");
        if (sender == null) {
            return "失败: NearbyControlSend.INSTANCE 为空";
        }
        Object type = enumConst(CLS_BLE_CONTROL_TYPE, typeName);
        if (type == null) {
            return "失败: BleControlType." + typeName + " 不存在，可选="
                    + enumNames(CLS_BLE_CONTROL_TYPE);
        }
        List<String> pool = dkIdPool();
        if (pool.isEmpty()) {
            return "失败: 尚无 dkId 候选（请在官方 APP 里用一次蓝牙钥匙以自动学习）";
        }

        StringBuilder trace = new StringBuilder();
        for (String id : pool) {
            for (String chName : CHANNEL_CANDIDATES) {
                Object channel = enumConst(CLS_CMD_CHANNEL, chName);
                if (channel == null) {
                    continue;
                }
                String r = trySend(sender, id, type, channel);
                trace.append("[").append(mask(id)).append("/").append(chName)
                        .append("]").append(r).append(" ");
                // 一旦真正提交/订阅成功就停止，避免重复下发同一条控制命令
                if (r.startsWith("已提交") || r.startsWith("返回")
                        || r.startsWith("已启动Flow")) {
                    return trace.toString();
                }
            }
        }
        return trace.toString();
    }

    /**
     * 订阅 channelFlow。sendControlCmd 的返回值是冷流（ChannelFlowBuilder），
     * 只有 launchIn/collect 之后，内部的 handleControlCommand 才会执行、
     * 才会通过 IVehDkConnService 向已连接的车端写入命令帧。
     *
     * 协程作用域优先用官方 APP 自己的 BleEventHandler.scope（Dispatchers.IO，
     * 生命周期与数字钥匙服务一致），取不到才退回 GlobalScope。
     */
    private static String subscribeFlow(Object flow, String tag) {
        Class<?> flowCls = cls("kotlinx.coroutines.flow.Flow");
        Class<?> scopeCls = cls("kotlinx.coroutines.CoroutineScope");
        if (flowCls == null || scopeCls == null) {
            return "失败: 缺少 kotlinx.coroutines.flow 类";
        }

        Object scope = staticField(CLS_BLE_EVENT, "scope");
        String scopeFrom = "BleEventHandler.scope";
        if (scope == null || !scopeCls.isInstance(scope)) {
            scope = staticField("kotlinx.coroutines.GlobalScope", "INSTANCE");
            scopeFrom = "GlobalScope";
        }
        if (scope == null || !scopeCls.isInstance(scope)) {
            return "失败: 拿不到 CoroutineScope";
        }

        // launchIn 定义在 Collect.kt，编译产物可能是 FlowKt facade 或 XXX__CollectKt
        String[] facades = {
                "kotlinx.coroutines.flow.FlowKt",
                "kotlinx.coroutines.flow.FlowKt__CollectKt",
                "kotlinx.coroutines.flow.FlowKt__BuildersKt",
                "kotlinx.coroutines.flow.FlowKt__ShareKt",
                "kotlinx.coroutines.flow.FlowKt__MergeKt",
        };
        for (String facade : facades) {
            Class<?> k = cls(facade);
            if (k == null) {
                continue;
            }
            for (Method m : k.getDeclaredMethods()) {
                if (!"launchIn".equals(m.getName())
                        || !Modifier.isStatic(m.getModifiers())) {
                    continue;
                }
                Class<?>[] p = m.getParameterTypes();
                if (p.length != 2 || !p[0].isInstance(flow)
                        || !p[1].isInstance(scope)) {
                    continue;
                }
                try {
                    m.setAccessible(true);
                    Object job = m.invoke(null, flow, scope);
                    ReconDumper.record("FLOW_SUBSCRIBED " + tag
                            + " via " + facade + " scope=" + scopeFrom
                            + " job=" + briefResult(job));
                    return "已启动Flow(job=" + String.valueOf(job) + ")";
                } catch (Throwable t) {
                    Throwable c = t.getCause() != null ? t.getCause() : t;
                    ReconDumper.record("FLOW_FAIL " + tag + " " + facade + " : " + c);
                }
            }
        }
        return "失败: 未找到可调用的 launchIn(Flow, CoroutineScope)";
    }

    private static String trySend(Object sender, String id, Object type, Object channel) {
        try {
            Method target = null;
            for (Method m : sender.getClass().getDeclaredMethods()) {
                if (!"sendControlCmd".equals(m.getName())) {
                    continue;
                }
                Class<?>[] p = m.getParameterTypes();
                if (p.length == 6 && p[0] == String.class && p[1].isEnum()
                        && p[2].isEnum() && p[3] == int.class
                        && p[4] == byte[].class) {
                    target = m;
                    break;
                }
            }
            if (target == null) {
                return "未找到 sendControlCmd 6 参重载";
            }
            target.setAccessible(true);
            Object cont = newContinuation("sendControlCmd/" + type);
            Object ret = target.invoke(sender, id, type, channel, 0,
                    new byte[0], cont);
            ReconDumper.record("SEND " + type + " via " + channel
                    + " dkId=" + mask(id) + " -> " + briefResult(ret));

            // sendControlCmd 由 channelFlow 构造：直接调用只返回冷流对象，
            // 内部 handleControlCommand 必须等 Flow 被订阅才会真正发帧。
            // 不订阅 = 命令从未发出（车端无任何反应）。
            Class<?> flowCls = cls("kotlinx.coroutines.flow.Flow");
            if (flowCls != null && flowCls.isInstance(ret)) {
                return subscribeFlow(ret, type + "/" + channel);
            }

            if (ret == null) {
                return "返回null";
            }
            String s = String.valueOf(ret);
            if (s.contains("COROUTINE_SUSPENDED")) {
                return "已提交(挂起)";
            }
            return "返回" + (s.length() > 80 ? s.substring(0, 80) : s);
        } catch (Throwable t) {
            Throwable cause = t.getCause() != null ? t.getCause() : t;
            ReconDumper.record("SEND_FAIL " + type + " via " + channel
                    + " : " + cause);
            return "异常:" + cause.getClass().getSimpleName()
                    + ":" + String.valueOf(cause.getMessage());
        }
    }

    /** 高层语义入口：NearbyControlImpl.controlDoor(CmdAction, CmdChannel, cont) */
    static String viaNearbyControlImpl(String typeName) {
        Class<?> impl = cls(CLS_NEARBY_IMPL);
        Object action = enumConst(CLS_CMD_ACTION, "Start");
        if (impl == null || action == null) {
            return "失败: 类或 CmdAction.Start 缺失";
        }
        try {
            Object inst = impl.newInstance();
            for (String chName : CHANNEL_CANDIDATES) {
                Object channel = enumConst(CLS_CMD_CHANNEL, chName);
                if (channel == null) {
                    continue;
                }
                for (Method m : impl.getDeclaredMethods()) {
                    if (!"controlDoor".equals(m.getName())) {
                        continue;
                    }
                    m.setAccessible(true);
                    Object cont = newContinuation("controlDoor/" + chName);
                    Object ret = m.invoke(inst, action, channel, cont);
                    ReconDumper.record("CTRL_DOOR via " + chName + " -> "
                            + briefResult(ret));
                    return "已提交(" + chName + ")";
                }
            }
            return "失败: 未找到 controlDoor";
        } catch (Throwable t) {
            Throwable c = t.getCause() != null ? t.getCause() : t;
            return "异常:" + c.getClass().getSimpleName()
                    + ":" + String.valueOf(c.getMessage());
        }
    }
}
