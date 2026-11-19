package com.pkauto.passivekey;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.util.Log;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * 常驻前台服务：跑 BLE 感知，命中状态机后通过桥接层驱动官方 APP。
 */
public class PassiveKeyService extends Service implements BleWatcher.Listener {

    private static final String TAG = "PK-Service";
    public static final String CHANNEL_ID = "pk_passive";
    private static final int NOTI_ID = 1001;

    private Prefs prefs;
    private BleWatcher watcher;
    private ExecutorService worker;
    private Handler handler;

    /** 供 UI 读取的运行时状态 */
    public static volatile boolean running = false;
    public static volatile String stateText = "未启动";
    public static volatile int lastRawRssi = 0;
    public static volatile int lastSmoothRssi = 0;
    public static volatile long lastEventAt = 0;
    public static volatile String lastEvent = "";
    public static volatile String bridgeInfo = "";
    public static final List<String> EVENTS = new ArrayList<String>();

    @Override
    public void onCreate() {
        super.onCreate();
        prefs = new Prefs(this);
        worker = Executors.newSingleThreadExecutor();
        handler = new Handler(Looper.getMainLooper());
        createChannel();
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        startForeground(NOTI_ID, buildNotification("准备中"));

        if (intent != null && intent.getBooleanExtra("stop", false)) {
            stopSelf();
            return START_NOT_STICKY;
        }

        final String testCmd = intent == null
                ? null : intent.getStringExtra("testcmd");

        if (watcher == null) {
            watcher = new BleWatcher(this, this);
        }

        // 感知层跑在官方 APP 进程内（避开 HyperOS 对本进程的冻结），
        // 这里只负责下发参数并查询状态。
        worker.execute(new Runnable() {
            @Override
            public void run() {
                String st = BridgeClient.send(PassiveKeyService.this, "STATUS");
                bridgeInfo = st;
                event("桥接: " + st);

                String mac = prefs.mac();
                if (mac == null || mac.isEmpty()) {
                    mac = prefs.macHint();
                    if (mac != null && !mac.isEmpty()) {
                        prefs.setMac(mac);
                    }
                }

                // 参数下发 + 启动模块内感知
                String cfg = "CONFIG " + prefs.near() + "," + prefs.far()
                        + "," + prefs.nearDwellMs() + "," + prefs.farDwellMs();
                String c = BridgeClient.send(PassiveKeyService.this, cfg);
                event("配置: " + c);

                String w = BridgeClient.send(PassiveKeyService.this, "START");
                event("感知: " + w);

                boolean alive = w != null && !w.startsWith("ERR");
                running = alive;
                stateText = alive ? "感知运行中（模块内）" : "感知未启动";
                updateNotification(alive
                        ? "监听中 · " + (mac == null || mac.isEmpty() ? "MAC未知" : mac)
                        : "模块未响应，请打开一次领克 APP");

                if (testCmd != null && !testCmd.isEmpty()) {
                    String r = BridgeClient.send(PassiveKeyService.this, testCmd);
                    event("TEST " + testCmd + " -> " + r);
                }
            }
        });

        handler.removeCallbacks(ticker);
        handler.postDelayed(ticker, 10000);

        return START_STICKY;
    }

    private final Runnable ticker = new Runnable() {
        @Override
        public void run() {
            if (worker != null && !worker.isShutdown()) {
                worker.execute(new Runnable() {
                    @Override
                    public void run() {
                        String s = BridgeClient.send(PassiveKeyService.this, "WSTATE");
                        if (s != null) {
                            bridgeInfo = s;
                            if (s.startsWith("WATCHER")) {
                                stateText = s.replace("WATCHER ", "");
                                running = s.contains("running=true");
                            } else if (s.startsWith("ERR")) {
                                running = false;
                                stateText = "模块未响应";
                            }
                        }
                    }
                });
            }
            handler.postDelayed(this, 15000);
        }
    };

    @Override
    public void onDestroy() {
        running = false;
        handler.removeCallbacksAndMessages(null);
        if (watcher != null) {
            watcher.stop();
            watcher = null;
        }
        if (worker != null) {
            worker.shutdownNow();
        }
        stateText = "已停止";
        super.onDestroy();
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    // ==================== BleWatcher 回调（Binder 线程） ====================

    @Override
    public void onApproach(int rssi) {
        stateText = "PRESENT(近场)";
        lastEventAt = System.currentTimeMillis();
        event("靠近 rssi=" + rssi);
        updateNotification("车内 · rssi " + rssi);
        if (!prefs.autoUnlock()) {
            event("自动解锁已关闭，仅记录");
            return;
        }
        worker.execute(new Runnable() {
            @Override
            public void run() {
                String r = BridgeClient.send(PassiveKeyService.this, "UNLOCK");
                event("UNLOCK -> " + r);
            }
        });
    }

    @Override
    public void onDepart(int rssi) {
        stateText = "AWAY(远离)";
        lastEventAt = System.currentTimeMillis();
        event("离开 rssi=" + rssi);
        updateNotification("远离 · rssi " + rssi);
        if (!prefs.autoLock()) {
            event("自动锁车已关闭，仅记录");
            return;
        }
        worker.execute(new Runnable() {
            @Override
            public void run() {
                String r = BridgeClient.send(PassiveKeyService.this, "LOCK");
                event("LOCK -> " + r);
            }
        });
    }

    @Override
    public void onRssi(int rawRssi, int smoothRssi, String state) {
        lastRawRssi = rawRssi;
        lastSmoothRssi = smoothRssi;
        stateText = state;
    }

    @Override
    public void onAnyDevice(String address, String name, int rssi) {
        // 定向模式下不使用
    }

    // ==================== 工具 ====================

    private void event(String msg) {
        Log.i(TAG, msg);
        synchronized (EVENTS) {
            EVENTS.add(0, timeStr() + "  " + msg);
            while (EVENTS.size() > 60) {
                EVENTS.remove(EVENTS.size() - 1);
            }
        }
        lastEvent = msg;
    }

    private static String timeStr() {
        java.text.SimpleDateFormat f =
                new java.text.SimpleDateFormat("HH:mm:ss", java.util.Locale.US);
        return f.format(new java.util.Date());
    }

    private void createChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationManager nm =
                    (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
            if (nm == null) {
                return;
            }
            NotificationChannel ch = new NotificationChannel(CHANNEL_ID,
                    "无感钥匙", NotificationManager.IMPORTANCE_LOW);
            ch.setDescription("蓝牙靠近解锁 / 远离锁车的常驻服务");
            ch.setShowBadge(false);
            nm.createNotificationChannel(ch);
        }
    }

    private Notification buildNotification(String text) {
        Intent i = new Intent(this, MainActivity.class);
        int flags = PendingIntent.FLAG_UPDATE_CURRENT;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            flags |= PendingIntent.FLAG_IMMUTABLE;
        }
        PendingIntent pi = PendingIntent.getActivity(this, 0, i, flags);

        Notification.Builder b;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            b = new Notification.Builder(this, CHANNEL_ID);
        } else {
            b = new Notification.Builder(this);
        }
        return b.setContentTitle("领克无感钥匙")
                .setContentText(text)
                .setSmallIcon(android.R.drawable.ic_menu_compass)
                .setContentIntent(pi)
                .setOngoing(true)
                .build();
    }

    private void updateNotification(String text) {
        try {
            NotificationManager nm =
                    (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
            if (nm != null) {
                nm.notify(NOTI_ID, buildNotification(text));
            }
        } catch (Throwable ignored) {
        }
    }

    public static void start(Context ctx) {
        Intent i = new Intent(ctx, PassiveKeyService.class);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            ctx.startForegroundService(i);
        } else {
            ctx.startService(i);
        }
    }

    public static void stop(Context ctx) {
        Intent i = new Intent(ctx, PassiveKeyService.class);
        i.putExtra("stop", true);
        ctx.startService(i);
    }
}
