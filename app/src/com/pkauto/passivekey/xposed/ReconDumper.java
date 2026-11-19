package com.pkauto.passivekey.xposed;

import android.content.Context;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Member;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Set;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;

/**
 * 侦察器：把目标类的方法/字段结构写入文件，并对关键方法挂追踪钩子，
 * 记录官方 APP 执行解锁/锁车时的真实调用链。
 *
 * 输出：/data/data/com.lynkco.customer/files/pk_recon.txt
 */
final class ReconDumper {

    static final String OUT_NAME = "pk_recon.txt";

    /** 需要 dump 结构的类（来自静态字符串池还原） */
    private static final String[] DUMP_CLASSES = {
            // ---- 控制入口 ----
            "com.geely.snc.basevehicle.control.IVehNearbyControl",
            "com.geely.snc.basevehicle.control.impl.NearbyControlImpl",
            "com.geely.snc.basevehicle.control.service.GLVehControlImpl",
            "com.geely.snc.basevehicle.control.impl.RemoteControlImpl",
            // ---- 命令参数 ----
            "com.geely.snc.basevehicle.control.request.CmdAction",
            "com.geely.snc.basevehicle.control.request.CmdChannel",
            "com.geely.snc.basevehicle.control.request.CmdName",
            "com.geely.snc.basevehicle.control.request.BleControlType",
            "com.geely.snc.basevehicle.control.request.CmdGeeaType",
            "com.geely.snc.basevehicle.control.request.BaseRequest",
            "com.geely.snc.basevehicle.control.request.CmdDoubleDoorAction",
            // ---- BLE 值枚举与发送 ----
            "com.geely.snc.basevehicle.control.ble.NearbyControlSend",
            "com.geely.snc.basevehicle.control.ble.ApproachUnlockValue",
            "com.geely.snc.basevehicle.control.ble.WalkAwayLockValue",
            "com.geely.snc.basevehicle.control.ble.DoorLockValue",
            "com.geely.snc.basevehicle.control.ble.DoorOpenValue",
            "com.geely.snc.basevehicle.control.ble.BleEventHandler",
            "com.geely.snc.basevehicle.control.ble.NearbyControlResultListener",
            "com.geely.snc.basevehicle.connection.IVehDkConnService",
            // ---- 请求 Bean ----
            "com.geely.snc.sdk.dkmanager.pri.bean.dk20.GlPriKeyApproachUnlockReqBean",
            "com.geely.snc.sdk.dkmanager.pri.bean.dk20.GlPriKeyWalkAwayLockReqBean",
            "com.ecarx.blekey.thirdadapter.service.MiuiService",
    };

    /** 需要挂调用追踪的类 */
    private static final String[] TRACE_CLASSES = {
            "com.geely.snc.basevehicle.control.impl.NearbyControlImpl",
            "com.geely.snc.basevehicle.control.service.GLVehControlImpl",
            "com.geely.snc.basevehicle.control.ble.NearbyControlSend",
            "com.geely.snc.basevehicle.control.impl.RemoteControlImpl",
            "com.geely.snc.basevehicle.control.ble.BleEventHandler",
            "com.geely.snc.basevehicle.control.ble.NearbyControlResultListener",
    };

    private static final Set<String> HOOKED = new LinkedHashSet<String>();
    private static final Object LOCK = new Object();
    private static Context appContext;
    private static ClassLoader classLoader;
    private static boolean headerWritten = false;

    private ReconDumper() {
    }

    // ================= 对外入口 =================

    static void attach(Context ctx, ClassLoader cl) {
        appContext = ctx;
        classLoader = cl;
        log("[RECON] attach, cl=" + (cl == null ? "null" : cl.getClass().getName()));
    }

    /** 阶段 1：dump 类结构 */
    static void dumpStructure() {
        StringBuilder sb = new StringBuilder();
        sb.append("\n\n########## 类结构 dump @ ")
                .append(now()).append(" ##########\n");

        for (String name : DUMP_CLASSES) {
            Class<?> c = load(name);
            if (c == null) {
                sb.append("\n### [缺失] ").append(name).append("\n");
                continue;
            }
            dumpClass(sb, c);
        }
        flush(sb.toString());
    }

    /** 阶段 2：给关键类挂调用追踪 */
    static void installTracers() {
        for (String name : TRACE_CLASSES) {
            Class<?> c = load(name);
            if (c == null) {
                log("[RECON] 追踪类缺失: " + name);
                continue;
            }
            hookAllMethods(c);
        }
    }

    // ================= dump 实现 =================

    private static void dumpClass(StringBuilder sb, Class<?> c) {
        sb.append("\n### ").append(c.getName()).append("\n");
        Class<?> sup = c.getSuperclass();
        sb.append("     extends ").append(sup == null ? "-" : sup.getName()).append("\n");

        Class<?>[] itfs = c.getInterfaces();
        if (itfs.length > 0) {
            sb.append("     implements");
            for (Class<?> i : itfs) {
                sb.append(" ").append(i.getName());
            }
            sb.append("\n");
        }

        // 静态字段（重点：找单例持有者）
        sb.append("\n  -- static fields --\n");
        for (Field f : safeFields(c)) {
            if (!Modifier.isStatic(f.getModifiers())) {
                continue;
            }
            String val;
            try {
                f.setAccessible(true);
                Object v = f.get(null);
                val = v == null ? "null" : brief(v);
            } catch (Throwable t) {
                val = "<读取失败:" + t.getClass().getSimpleName() + ">";
            }
            sb.append("    ").append(mods(f.getModifiers())).append(" ")
                    .append(f.getType().getName()).append(" ").append(f.getName())
                    .append(" = ").append(val).append("\n");
        }

        // 实例字段
        sb.append("\n  -- instance fields --\n");
        for (Field f : safeFields(c)) {
            if (Modifier.isStatic(f.getModifiers())) {
                continue;
            }
            sb.append("    ").append(mods(f.getModifiers())).append(" ")
                    .append(f.getType().getName()).append(" ").append(f.getName())
                    .append("\n");
        }

        // 构造器
        sb.append("\n  -- constructors --\n");
        try {
            for (Constructor<?> ct : c.getDeclaredConstructors()) {
                sb.append("    ").append(mods(ct.getModifiers())).append(" <init>")
                        .append(sig(ct.getParameterTypes())).append("\n");
            }
        } catch (Throwable ignored) {
        }

        // 方法
        sb.append("\n  -- methods --\n");
        Method[] ms;
        try {
            ms = c.getDeclaredMethods();
        } catch (Throwable t) {
            ms = new Method[0];
        }
        for (Method m : ms) {
            sb.append("    ").append(mods(m.getModifiers())).append(" ")
                    .append(m.getReturnType().getName()).append(" ")
                    .append(m.getName())
                    .append(sig(m.getParameterTypes())).append("\n");
        }
        sb.append("\n");
    }

    // ================= hook 实现 =================

    private static void hookAllMethods(Class<?> c) {
        Method[] ms;
        try {
            ms = c.getDeclaredMethods();
        } catch (Throwable t) {
            return;
        }
        for (final Method m : ms) {
            final String key = c.getName() + "#" + m.getName()
                    + sig(m.getParameterTypes());
            synchronized (LOCK) {
                if (HOOKED.contains(key)) {
                    continue;
                }
                HOOKED.add(key);
            }
            try {
                XposedBridge.hookMethod(m, new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam p) {
                        try {
                            record("CALL " + shortName(m) + "\n"
                                    + "      this=" + brief(p.thisObject) + "\n"
                                    + "      args=" + args(p.args));
                        } catch (Throwable ignored) {
                        }
                    }

                    @Override
                    protected void afterHookedMethod(MethodHookParam p) {
                        try {
                            StringBuilder sb = new StringBuilder();
                            sb.append("RET  ").append(shortName(m));
                            if (p.hasThrowable()) {
                                sb.append("\n      EX=")
                                        .append(stack(p.getThrowable()));
                            } else {
                                sb.append("\n      -> ").append(brief(p.getResult()));
                            }
                            record(sb.toString());
                        } catch (Throwable ignored) {
                        }
                    }
                });
                log("[RECON] hooked " + key);
            } catch (Throwable t) {
                log("[RECON] hook 失败 " + key + " : " + t);
            }
        }
    }

    // ================= 工具 =================

    private static Class<?> load(String name) {
        try {
            return Class.forName(name, true, classLoader);
        } catch (Throwable t) {
            return null;
        }
    }

    private static Field[] safeFields(Class<?> c) {
        try {
            return c.getDeclaredFields();
        } catch (Throwable t) {
            return new Field[0];
        }
    }

    private static String sig(Class<?>[] pts) {
        StringBuilder sb = new StringBuilder("(");
        for (int i = 0; i < pts.length; i++) {
            if (i > 0) {
                sb.append(", ");
            }
            sb.append(pts[i].getName());
        }
        return sb.append(")").toString();
    }

    private static String shortName(Member m) {
        String cn = m.getDeclaringClass().getSimpleName();
        if (m instanceof Method) {
            Method mm = (Method) m;
            return cn + "." + mm.getName() + sig(mm.getParameterTypes());
        }
        return cn + "." + m.getName();
    }

    private static String args(Object[] a) {
        if (a == null) {
            return "null";
        }
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < a.length; i++) {
            if (i > 0) {
                sb.append(", ");
            }
            sb.append(brief(a[i]));
        }
        return sb.append("]").toString();
    }

    private static String brief(Object o) {
        if (o == null) {
            return "null";
        }
        String cn = o.getClass().getName();
        // Continuation 之类没意义的直接省略
        if (cn.startsWith("kotlin.coroutines.")) {
            return "<" + cn + ">";
        }
        String s;
        try {
            s = String.valueOf(o);
        } catch (Throwable t) {
            s = "<toString 异常>";
        }
        if (s.length() > 300) {
            s = s.substring(0, 300) + "…";
        }
        return cn + "{" + s + "}";
    }

    private static String stack(Throwable t) {
        if (t == null) {
            return "null";
        }
        try {
            StringWriter sw = new StringWriter();
            t.printStackTrace(new PrintWriter(sw));
            String s = sw.toString();
            return s.length() > 1200 ? s.substring(0, 1200) : s;
        } catch (Throwable x) {
            return String.valueOf(t);
        }
    }

    private static String mods(int m) {
        StringBuilder sb = new StringBuilder();
        if (Modifier.isPublic(m)) sb.append("public ");
        if (Modifier.isPrivate(m)) sb.append("private ");
        if (Modifier.isProtected(m)) sb.append("protected ");
        if (Modifier.isStatic(m)) sb.append("static ");
        if (Modifier.isFinal(m)) sb.append("final ");
        if (Modifier.isAbstract(m)) sb.append("abstract ");
        if (Modifier.isNative(m)) sb.append("native ");
        return sb.toString().trim();
    }

    private static String now() {
        return new SimpleDateFormat("MM-dd HH:mm:ss.SSS", Locale.US)
                .format(new Date());
    }

    /** 实时写文件（带时间戳，便于对照操作时间） */
    static void record(String text) {
        flush("[" + now() + "] " + text + "\n");
    }

    private static synchronized void flush(String text) {
        if (appContext == null) {
            XposedBridge.log("[RECON-noctx] " + text);
            return;
        }
        FileOutputStream fos = null;
        try {
            File dir = appContext.getFilesDir();
            if (dir == null) {
                return;
            }
            File f = new File(dir, OUT_NAME);
            fos = new FileOutputStream(f, true);
            String head = "";
            if (!headerWritten) {
                headerWritten = true;
                head = "=== PassiveKey Recon log ===\n";
            }
            fos.write((head + text).getBytes("UTF-8"));
            fos.flush();
        } catch (IOException e) {
            XposedBridge.log("[RECON-io] " + e);
        } catch (Throwable t) {
            XposedBridge.log("[RECON-write] " + t);
        } finally {
            if (fos != null) {
                try {
                    fos.close();
                } catch (IOException ignored) {
                }
            }
        }
    }

    static void log(String s) {
        XposedBridge.log("[PassiveKey] " + s);
    }
}
