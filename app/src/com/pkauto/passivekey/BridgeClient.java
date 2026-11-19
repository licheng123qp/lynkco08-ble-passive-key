package com.pkauto.passivekey;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.Build;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * 与官方 APP 进程内的桥接模块通信（显式广播通道）。
 *
 * 请求：com.pkauto.passivekey.CMD  -> 官方 APP 进程内的模块
 * 回执：com.pkauto.passivekey.RESP -> 本应用
 */
public final class BridgeClient {

    private static final String ACTION_CMD = "com.pkauto.passivekey.CMD";
    private static final String ACTION_RESP = "com.pkauto.passivekey.RESP";
    private static final String TARGET_PKG = "com.lynkco.customer";
    private static final String TOKEN = "pk-8f3a1c";
    private static final long TIMEOUT_MS = 4000;

    private static final AtomicInteger SEQ = new AtomicInteger(1000);

    private BridgeClient() {
    }

    /** 同步请求-响应；必须在后台线程调用 */
    public static String send(Context ctx, String cmd) {
        final Context app = ctx.getApplicationContext();
        final int seq = SEQ.incrementAndGet();
        final CountDownLatch latch = new CountDownLatch(1);
        final String[] result = {"ERR 超时（模块未响应）"};

        BroadcastReceiver receiver = new BroadcastReceiver() {
            @Override
            public void onReceive(Context context, Intent intent) {
                if (intent == null || intent.getIntExtra("seq", -1) != seq) {
                    return;
                }
                String resp = intent.getStringExtra("resp");
                result[0] = resp == null ? "ERR 空响应" : resp;

                // 顺带把模块侧已知的 MAC / dkId 学回来
                String mac = intent.getStringExtra("mac");
                if (mac != null && !mac.isEmpty()) {
                    Prefs p = new Prefs(app);
                    if (!mac.equalsIgnoreCase(p.macHint())) {
                        p.setMacHint(mac);
                        if (p.mac() == null || p.mac().isEmpty()) {
                            p.setMac(mac);
                        }
                    }
                }
                latch.countDown();
            }
        };

        try {
            IntentFilter f = new IntentFilter(ACTION_RESP);
            if (Build.VERSION.SDK_INT >= 33) {
                app.registerReceiver(receiver, f, Context.RECEIVER_EXPORTED);
            } else {
                app.registerReceiver(receiver, f);
            }
        } catch (Throwable t) {
            return "ERR 注册接收器失败: " + t.getMessage();
        }

        try {
            Intent i = new Intent(ACTION_CMD);
            i.setPackage(TARGET_PKG);
            i.putExtra("cmd", cmd);
            i.putExtra("seq", seq);
            i.putExtra("token", TOKEN);
            app.sendBroadcast(i);

            if (!latch.await(TIMEOUT_MS, TimeUnit.MILLISECONDS)) {
                return "ERR 超时（模块未响应，官方 APP 可能未运行）";
            }
            return result[0];
        } catch (Throwable t) {
            return "ERR " + t.getClass().getSimpleName() + ": " + t.getMessage();
        } finally {
            try {
                app.unregisterReceiver(receiver);
            } catch (Throwable ignored) {
            }
        }
    }

    public static String ping(Context ctx) {
        return send(ctx, "PING");
    }
}
