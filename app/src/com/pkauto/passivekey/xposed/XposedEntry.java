package com.pkauto.passivekey.xposed;

import android.app.Application;
import android.app.Instrumentation;
import android.content.Context;

import java.lang.reflect.Method;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam;

/**
 * LSPosed 模块入口（运行在官方 APP 进程内）。
 *
 * 职责：
 *  1. 启动 BridgeServer，等待自研 APP 的解锁/上锁指令；
 *  2. 从 MMKV 预载 dkId 候选与车机 MAC；
 *  3. 挂学习钩子，从真实调用中捕获 dkId；
 *  4. 首轮结构 dump（便于排障）。
 */
public class XposedEntry implements IXposedHookLoadPackage {

    static final String TARGET_PKG = "com.lynkco.customer";

    /** 是否做结构 dump（排障时可开，稳定后建议关掉以减少开销） */
    private static final boolean ENABLE_RECON_DUMP = true;

    @Override
    public void handleLoadPackage(LoadPackageParam lpparam) {
        if (!TARGET_PKG.equals(lpparam.packageName)) {
            return;
        }
        ReconDumper.log("模块已注入 " + TARGET_PKG
                + " / process=" + lpparam.processName);

        try {
            hookApplicationOnCreate();
        } catch (Throwable t) {
            ReconDumper.log("hook Application 失败: " + t);
        }
        try {
            hookInstrumentation();
        } catch (Throwable t) {
            ReconDumper.log("hook Instrumentation 失败: " + t);
        }
    }

    private void hookApplicationOnCreate() {
        XposedBridge.hookAllMethods(Application.class, "onCreate",
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) {
                        if (!(param.thisObject instanceof Application)) {
                            return;
                        }
                        Application app = (Application) param.thisObject;
                        bootstrap(app, app.getClassLoader(), "Application.onCreate");
                    }
                });
    }

    private void hookInstrumentation() {
        XposedBridge.hookAllMethods(Instrumentation.class,
                "callApplicationOnCreate", new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) {
                        if (param.args == null || param.args.length == 0) {
                            return;
                        }
                        if (!(param.args[0] instanceof Application)) {
                            return;
                        }
                        Application app = (Application) param.args[0];
                        bootstrap(app, app.getClassLoader(), "Instrumentation");
                    }
                });
    }

    private volatile boolean started = false;

    private void bootstrap(final Context ctx, final ClassLoader cl,
                           final String from) {
        if (started) {
            return;
        }
        started = true;

        ReconDumper.attach(ctx, cl);
        ReconDumper.log("引导成功（来自 " + from + "）");

        try {
            DkBridge.init(cl);
            // 预载配置：dkId 候选 + 车机 MAC
            DkBridge.loadFromMmkv(ctx.getFilesDir());
        } catch (Throwable t) {
            ReconDumper.log("配置预载失败: " + t);
        }

        // 立刻启动桥接服务，越早越好
        try {
            BridgeServer.start(cl);
        } catch (Throwable t) {
            ReconDumper.log("BridgeServer 启动失败: " + t);
        }

        // 主通道：显式广播（LocalSocket 跨 UID 被 SELinux 拦截）
        try {
            BridgeReceiver.register(ctx);
        } catch (Throwable t) {
            ReconDumper.log("BridgeReceiver 注册失败: " + t);
        }

        Thread t = new Thread(new Runnable() {
            @Override
            public void run() {
                // 等目标类加载后再挂钩子
                for (int i = 0; i < 6; i++) {
                    sleep(i == 0 ? 3000 : 5000);
                    boolean ok = installLearners(cl);
                    if (ok) {
                        break;
                    }
                }
                if (ENABLE_RECON_DUMP) {
                    sleep(2000);
                    try {
                        ReconDumper.dumpStructure();
                    } catch (Throwable x) {
                        ReconDumper.log("dump 失败: " + x);
                    }
                }

                // 感知层：跑在官方 APP 进程内，自动开始
                try {
                    ModuleWatcher.init(ctx);
                    sleep(1000);
                    ModuleWatcher.start();
                } catch (Throwable x) {
                    ReconDumper.log("感知层启动失败: " + x);
                }

                ReconDumper.log("模块就绪，等待指令");
            }
        }, "pk-init");
        t.setDaemon(true);
        t.start();
    }

    /**
     * 挂 dkId 学习钩子：从官方真实调用里捕获那把钥匙的标识。
     * 只 hook 首个参数确定为 dkId 的方法，避免学到 sessionId 等无关串。
     */
    private boolean installLearners(ClassLoader cl) {
        boolean any = false;
        any |= hookFirstStringArg(cl, DkBridge.CLS_NEARBY_SEND,
                "checkDkBaseListener");
        any |= hookFirstStringArg(cl, DkBridge.CLS_NEARBY_SEND,
                "sendControlCmd");
        return any;
    }

    private boolean hookFirstStringArg(ClassLoader cl, String clsName,
                                       final String methodName) {
        Class<?> c;
        try {
            c = Class.forName(clsName, true, cl);
        } catch (Throwable t) {
            return false;
        }
        boolean hooked = false;
        try {
            for (final Method m : c.getDeclaredMethods()) {
                if (!m.getName().equals(methodName)) {
                    continue;
                }
                Class<?>[] p = m.getParameterTypes();
                if (p.length == 0 || p[0] != String.class) {
                    continue;
                }
                XposedBridge.hookMethod(m, new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) {
                        try {
                            if (param.args != null && param.args.length > 0
                                    && param.args[0] instanceof String) {
                                DkBridge.learnDkId((String) param.args[0]);
                            }
                        } catch (Throwable ignored) {
                        }
                    }
                });
                hooked = true;
            }
        } catch (Throwable t) {
            ReconDumper.log("挂学习钩子失败 " + methodName + ": " + t);
        }
        if (hooked) {
            ReconDumper.log("学习钩子就绪: " + methodName);
        }
        return hooked;
    }

    private static void sleep(long ms) {
        try {
            Thread.sleep(ms);
        } catch (InterruptedException ignored) {
        }
    }
}
