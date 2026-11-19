package com.pkauto.passivekey.xposed;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.PackageManager;
import android.os.Build;

import java.lang.reflect.Method;

/**
 * 广播桥：接收自研 APP 的指令并在官方 APP 进程内执行。
 *
 * 为什么用广播而不是 LocalSocket：Android 12+ 的 SELinux 禁止跨 UID 的
 * 抽象 unix socket 连接（实测 Permission denied），而显式广播（setPackage）
 * 不受此限制，且能唤醒处于后台/缓存态的官方 APP 进程 —— 这正是本方案所需。
 *
 * 安全：校验发送方 UID 必须等于自研 APP 的 uid；同时校验共享 token，
 * 防止其它应用误触或伪造。
 */
final class BridgeReceiver {

    static final String ACTION_CMD = "com.pkauto.passivekey.CMD";
    static final String ACTION_RESP = "com.pkauto.passivekey.RESP";
    static final String EXTRA_CMD = "cmd";
    static final String EXTRA_SEQ = "seq";

    static final String PKG_CONTROLLER = "com.pkauto.passivekey";
    /** 共享 token：挡住偶然的同 action 广播 */
    private static final String TOKEN = "pk-8f3a1c";

    private static boolean registered = false;
    private static Context appCtx;
    private static int controllerUid = -1;

    private BridgeReceiver() {
    }

    static synchronized void register(Context ctx) {
        if (registered) {
            return;
        }
        if (ctx == null) {
            ReconDumper.log("BridgeReceiver: 无 Context，无法注册");
            return;
        }
        appCtx = ctx.getApplicationContext() != null
                ? ctx.getApplicationContext() : ctx;

        try {
            PackageManager pm = appCtx.getPackageManager();
            controllerUid = pm.getPackageInfo(PKG_CONTROLLER, 0).applicationInfo.uid;
            ReconDumper.log("控制端 uid = " + controllerUid);
        } catch (Throwable t) {
            ReconDumper.log("未找到控制端应用（未安装？）: " + t);
        }

        IntentFilter f = new IntentFilter(ACTION_CMD);
        BroadcastReceiver r = new BroadcastReceiver() {
            @Override
            public void onReceive(Context context, Intent intent) {
                try {
                    handle(this, intent);
                } catch (Throwable t) {
                    ReconDumper.log("处理指令异常: " + t);
                }
            }
        };
        try {
            if (Build.VERSION.SDK_INT >= 33) {
                appCtx.registerReceiver(r, f, Context.RECEIVER_EXPORTED);
            } else {
                appCtx.registerReceiver(r, f);
            }
            registered = true;
            ReconDumper.log("BridgeReceiver 已注册");
        } catch (Throwable t) {
            ReconDumper.log("注册广播失败: " + t);
        }
    }

    private static void handle(BroadcastReceiver r, Intent intent) {
        if (intent == null) {
            return;
        }
        // --- 来源校验 ---
        int fromUid = senderUid(r);
        if (controllerUid > 0 && fromUid > 0 && fromUid != controllerUid) {
            ReconDumper.log("拒绝来源 uid=" + fromUid + " 的指令");
            return;
        }
        String token = intent.getStringExtra("token");
        if (!TOKEN.equals(token)) {
            ReconDumper.log("拒绝 token 不匹配的指令");
            return;
        }

        String cmd = intent.getStringExtra(EXTRA_CMD);
        int seq = intent.getIntExtra(EXTRA_SEQ, 0);
        if (cmd == null || cmd.isEmpty()) {
            return;
        }

        String resp = dispatch(cmd);
        reply(seq, resp);
    }

    /** API 34+ 可用，低版本返回 -1（此时只靠 token 兜底） */
    private static int senderUid(BroadcastReceiver r) {
        if (Build.VERSION.SDK_INT < 34) {
            return -1;
        }
        try {
            Method m = BroadcastReceiver.class.getMethod("getSentFromUid");
            Object v = m.invoke(r);
            return v instanceof Integer ? (Integer) v : -1;
        } catch (Throwable t) {
            return -1;
        }
    }

    private static void reply(int seq, String resp) {
        try {
            Intent i = new Intent(ACTION_RESP);
            i.setPackage(PKG_CONTROLLER);
            i.putExtra(EXTRA_SEQ, seq);
            i.putExtra("resp", resp);
            i.putExtra("mac", DkBridge.getVehicleMac());
            i.putExtra("dkid", DkBridge.getDkId());
            appCtx.sendBroadcast(i);
        } catch (Throwable t) {
            ReconDumper.log("回传结果失败: " + t);
        }
    }

    private static String dispatch(String cmd) {
        ReconDumper.record("CMD " + cmd);
        try {
            if ("PING".equals(cmd)) {
                return "PONG mac=" + DkBridge.getVehicleMac()
                        + " dkId=" + DkBridge.mask(DkBridge.getDkId());
            }
            if ("STATUS".equals(cmd)) {
                return "STATUS dkId=" + DkBridge.mask(DkBridge.getDkId())
                        + " " + DkBridge.connectionStatus();
            }
            if ("UNLOCK".equals(cmd)) {
                return "OK " + DkBridge.sendBleCommand("DOOR_UNLOCK");
            }
            if ("LOCK".equals(cmd)) {
                return "OK " + DkBridge.sendBleCommand("DOOR_LOCK");
            }
            if ("APPROACH_ON".equals(cmd)) {
                return "OK " + DkBridge.sendBleCommand("APPROACH_UNLOCK_OPEN");
            }
            if ("APPROACH_OFF".equals(cmd)) {
                return "OK " + DkBridge.sendBleCommand("APPROACH_UNLOCK_CLOSE");
            }
            if ("WALKAWAY_ON".equals(cmd)) {
                return "OK " + DkBridge.sendBleCommand("WALKAWAY_LOCK_OPEN");
            }
            if ("WALKAWAY_OFF".equals(cmd)) {
                return "OK " + DkBridge.sendBleCommand("WALKAWAY_LOCK_CLOSE");
            }
            if ("DOOR".equals(cmd)) {
                return "OK " + DkBridge.viaNearbyControlImpl("DOOR_UNLOCK");
            }
            if ("ENUMS".equals(cmd)) {
                return "BleControlType=" + DkBridge.enumNames(DkBridge.CLS_BLE_CONTROL_TYPE)
                        + " CmdChannel=" + DkBridge.enumNames(DkBridge.CLS_CMD_CHANNEL);
            }
            if ("START".equals(cmd)) {
                ModuleWatcher.start();
                return "OK watcher=" + ModuleWatcher.status();
            }
            if ("STOP".equals(cmd)) {
                ModuleWatcher.stop();
                return "OK watcher stopped";
            }
            if ("WSTATE".equals(cmd)) {
                return "WATCHER " + ModuleWatcher.status();
            }
            if ("SCANALL".equals(cmd)) {
                return ModuleWatcher.startDiag();
            }
            if ("SCANRESULT".equals(cmd)) {
                return ModuleWatcher.diagResult();
            }
            if (cmd.startsWith("CONFIG ")) {
                String[] p = cmd.substring(7).trim().split(",");
                if (p.length >= 4) {
                    try {
                        ModuleWatcher.configure(
                                Integer.parseInt(p[0].trim()),
                                Integer.parseInt(p[1].trim()),
                                Integer.parseInt(p[2].trim()),
                                Integer.parseInt(p[3].trim()));
                        return "OK " + ModuleWatcher.status();
                    } catch (NumberFormatException e) {
                        return "ERR 参数格式应为 near,far,nearDwell,farDwell";
                    }
                }
                return "ERR CONFIG 需要 4 个数字";
            }
            if (cmd.startsWith("SETDKID ")) {
                DkBridge.learnDkId(cmd.substring(8).trim());
                return "OK dkId=" + DkBridge.mask(DkBridge.getDkId());
            }
            return "ERR unknown command";
        } catch (Throwable t) {
            ReconDumper.record("CMD_FAIL " + cmd + " : " + t);
            return "ERR " + t.getClass().getSimpleName() + ": " + t.getMessage();
        }
    }
}
