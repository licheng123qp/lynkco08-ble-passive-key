package com.pkauto.passivekey.xposed;

import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothManager;
import android.bluetooth.le.BluetoothLeScanner;
import android.bluetooth.le.ScanCallback;
import android.bluetooth.le.ScanFilter;
import android.bluetooth.le.ScanResult;
import android.bluetooth.le.ScanSettings;
import android.content.Context;
import android.os.Build;
import android.os.Handler;
import android.os.HandlerThread;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 模块内 BLE 感知器。
 *
 * 为什么放在官方 APP 进程里而不是自研 APP：
 *  - 自研 APP 在 HyperOS 上会被 Greezer 冻结（实测进程状态 do_freezer_trap），
 *    后台扫描必然停摆；
 *  - 官方 APP 的 dkservice 常驻且持有 BLUETOOTH_SCAN / BLUETOOTH_PRIVILEGED，
 *    本身就为蓝牙钥匙做保活，搭这趟车比自建保活可靠得多；
 *  - 命中后直接在同进程内调 DkBridge，没有跨进程延迟。
 *
 * 扫描必须带 ScanFilter(deviceAddress)，否则息屏后会被系统按每 30 分钟限流。
 */
final class ModuleWatcher {

    private static final String TAG = "[PassiveKey] ";

    private static Context ctx;
    private static HandlerThread thread;
    private static Handler handler;

    private static BluetoothLeScanner scanner;
    private static ScanCallback callback;

    private static volatile boolean running = false;

    // ---- 可调参数 ----
    private static int nearThreshold = -75;
    private static int farThreshold = -82;
    /** 驻留门槛，单位毫秒，按真实时间累计 */
    private static long nearDwellMs = 4500;
    private static long farDwellMs = 4500;
    private static long unlockCooldownMs = 20000;
    private static long lockCooldownMs = 15000;
    private static long lostTimeoutMs = 45000;

    private static final int WIN_SIZE = 8;
    private static final int[] WIN = new int[WIN_SIZE];
    private static int winCount = 0;
    private static int winPos = 0;

    private static boolean present = false;
    /** 连续满足条件的起始时刻，0 表示当前不满足 */
    private static long nearSinceAt = 0;
    private static long farSinceAt = 0;
    private static long lastUnlockAt = 0;
    private static long lastLockAt = 0;
    private static long lastSeenAt = 0;
    private static int lastSmooth = 0;
    private static int scanHitCount = 0;

    // ---- 诊断：无过滤短扫描，确认车机实际广播地址 ----
    private static final ConcurrentHashMap<String, Integer> diagSeen =
            new ConcurrentHashMap<String, Integer>();
    private static BluetoothLeScanner diagScanner;
    private static ScanCallback diagCallback;
    private static volatile long diagStartAt = 0;
    private static volatile int diagHitTarget = 0;

    private ModuleWatcher() {
    }

    static void init(Context context) {
        ctx = context;
        thread = new HandlerThread("pk-scan");
        thread.start();
        handler = new Handler(thread.getLooper());
        // 周期性检查"目标消失"
        handler.post(new Runnable() {
            @Override
            public void run() {
                try {
                    lostCheck();
                } catch (Throwable ignored) {
                }
                if (handler != null) {
                    handler.postDelayed(this, 10000);
                }
            }
        });
    }

    static void start() {
        if (running) {
            return;
        }
        final String mac = DkBridge.getVehicleMac();
        if (mac == null || mac.isEmpty()) {
            ReconDumper.log("感知启动失败：未知车机 MAC");
            return;
        }
        if (ctx == null) {
            ReconDumper.log("感知启动失败：无 Context");
            return;
        }
        handler.post(new Runnable() {
            @Override
            public void run() {
                doStart(mac);
            }
        });
    }

    private static void doStart(String mac) {
        try {
            BluetoothManager bm =
                    (BluetoothManager) ctx.getSystemService(Context.BLUETOOTH_SERVICE);
            BluetoothAdapter ad = bm == null ? null : bm.getAdapter();
            if (ad == null || !ad.isEnabled()) {
                ReconDumper.log("感知启动失败：蓝牙未开启");
                return;
            }
            scanner = ad.getBluetoothLeScanner();
            if (scanner == null) {
                ReconDumper.log("感知启动失败：无扫描器");
                return;
            }

            callback = new ScanCallback() {
                @Override
                public void onScanResult(int type, ScanResult result) {
                    onResult(result);
                }

                @Override
                public void onScanFailed(int errorCode) {
                    ReconDumper.log("扫描失败 errorCode=" + errorCode);
                }
            };

            List<ScanFilter> filters = new ArrayList<ScanFilter>();
            filters.add(new ScanFilter.Builder().setDeviceAddress(mac).build());

            ScanSettings settings = new ScanSettings.Builder()
                    .setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY)
                    .setReportDelay(0)
                    .build();

            scanner.startScan(filters, settings, callback);
            running = true;
            reset();
            ReconDumper.log("感知已启动 MAC=" + mac
                    + " 阈值 近>=" + nearThreshold + " 远<=" + farThreshold
                    + " 驻留=" + (nearDwellMs / 1000f) + "s/" + (farDwellMs / 1000f) + "s");
            ReconDumper.record("WATCHER_START mac=" + mac);
        } catch (Throwable t) {
            ReconDumper.log("感知启动异常: " + t);
        }
    }

    static void stop() {
        running = false;
        if (scanner != null && callback != null) {
            try {
                scanner.stopScan(callback);
            } catch (Throwable ignored) {
            }
        }
        scanner = null;
        callback = null;
        ReconDumper.log("感知已停止");
    }

    static void configure(int near, int far, int ndMs, int fdMs) {
        nearThreshold = near;
        farThreshold = far;
        nearDwellMs = Math.max(200, ndMs);
        farDwellMs = Math.max(200, fdMs);
        ReconDumper.log("感知参数更新: 近>=" + near + " 远<=" + far
                + " 驻留=" + nearDwellMs + "/" + farDwellMs + "ms");
    }

    /**
     * 启动 10 秒无过滤扫描。只在排查时用（无过滤扫描息屏后会被系统限流，
     * 因此常驻感知仍必须用 MAC 过滤）。用于确认车机是否在广播、真实地址是什么。
     */
    static String startDiag() {
        try {
            if (ctx == null) {
                return "ERR 无 Context";
            }
            BluetoothManager bm =
                    (BluetoothManager) ctx.getSystemService(Context.BLUETOOTH_SERVICE);
            BluetoothAdapter ad = bm == null ? null : bm.getAdapter();
            if (ad == null || !ad.isEnabled()) {
                return "ERR 蓝牙未开启";
            }
            BluetoothLeScanner s = ad.getBluetoothLeScanner();
            if (s == null) {
                return "ERR 无扫描器";
            }
            stopDiag();
            diagSeen.clear();
            diagHitTarget = 0;
            diagStartAt = System.currentTimeMillis();

            diagCallback = new ScanCallback() {
                @Override
                public void onScanResult(int callbackType, ScanResult r) {
                    try {
                        BluetoothDevice dev = r.getDevice();
                        if (dev == null) {
                            return;
                        }
                        String addr = dev.getAddress();
                        String name = "";
                        try {
                            String n = dev.getName();
                            if (n != null) {
                                name = n;
                            }
                        } catch (Throwable ignored) {
                        }
                        int rssi = r.getRssi();
                        String key = addr + "|" + name;
                        Integer old = diagSeen.get(key);
                        if (old == null || rssi > old) {
                            diagSeen.put(key, rssi);
                        }
                        String target = DkBridge.getVehicleMac();
                        if (target != null && addr.equalsIgnoreCase(target)) {
                            diagHitTarget++;
                            ReconDumper.record("DIAG_TARGET_HIT " + addr
                                    + " rssi=" + rssi + " name=" + name);
                        }
                    } catch (Throwable ignored) {
                    }
                }

                @Override
                public void onScanFailed(int errorCode) {
                    ReconDumper.log("诊断扫描失败 errorCode=" + errorCode);
                }
            };

            s.startScan(null, new ScanSettings.Builder()
                    .setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY)
                    .setReportDelay(0)
                    .build(), diagCallback);
            diagScanner = s;
            ReconDumper.log("诊断扫描启动（10s，无过滤）");
            if (handler != null) {
                handler.postDelayed(new Runnable() {
                    @Override
                    public void run() {
                        stopDiag();
                        ReconDumper.log("诊断扫描结束，命中目标 " + diagHitTarget + " 次");
                    }
                }, 10000);
            }
            return "OK 无过滤扫描 10s 已启动，之后发 SCANRESULT";
        } catch (Throwable t) {
            return "ERR " + t;
        }
    }

    private static void stopDiag() {
        if (diagScanner != null && diagCallback != null) {
            try {
                diagScanner.stopScan(diagCallback);
            } catch (Throwable ignored) {
            }
        }
        diagScanner = null;
        diagCallback = null;
    }

    /** 返回信号最强的 25 个设备，附目标 MAC 命中次数 */
    static String diagResult() {
        List<Map.Entry<String, Integer>> list =
                new ArrayList<Map.Entry<String, Integer>>(diagSeen.entrySet());
        Collections.sort(list, new Comparator<Map.Entry<String, Integer>>() {
            @Override
            public int compare(Map.Entry<String, Integer> a,
                               Map.Entry<String, Integer> b) {
                return b.getValue().compareTo(a.getValue());
            }
        });
        StringBuilder sb = new StringBuilder();
        long sec = diagStartAt > 0
                ? (System.currentTimeMillis() - diagStartAt) / 1000 : 0;
        String target = DkBridge.getVehicleMac();
        sb.append("无过滤扫描 ").append(sec).append("s，设备 ")
                .append(list.size()).append(" 个，目标 ")
                .append(target).append(" 命中 ").append(diagHitTarget).append(" 次\n");
        int n = 0;
        for (Map.Entry<String, Integer> e : list) {
            String[] f = e.getKey().split("\\|", 2);
            sb.append(f[0]).append("  ").append(e.getValue()).append("dBm");
            if (f.length > 1 && f[1].length() > 0) {
                sb.append("  ").append(f[1]);
            }
            sb.append("\n");
            if (++n >= 25) {
                break;
            }
        }
        if (list.isEmpty()) {
            sb.append("（没有任何广播，检查蓝牙/定位权限与车机是否唤醒）");
        }
        return sb.toString();
    }

    static String status() {
        return "running=" + running
                + " present=" + present
                + " hits=" + scanHitCount
                + " smooth=" + lastSmooth
                + " near>=" + nearThreshold
                + " far<=" + farThreshold
                + " dwell=" + nearDwellMs + "/" + farDwellMs + "ms";
    }

    // ==================== 核心判定 ====================

    private static synchronized void onResult(ScanResult r) {
        if (!running || r == null) {
            return;
        }
        long now = System.currentTimeMillis();
        lastSeenAt = now;
        scanHitCount++;

        int rssi = r.getRssi();
        push(rssi);
        int smooth = median();
        lastSmooth = smooth;

        long sinceUnlock = now - lastUnlockAt;
        long sinceLock = now - lastLockAt;

        if (!present) {
            if (smooth >= nearThreshold) {
                if (nearSinceAt == 0) {
                    nearSinceAt = now;
                }
                if (now - nearSinceAt >= nearDwellMs && sinceUnlock >= unlockCooldownMs) {
                    long held = now - nearSinceAt;
                    present = true;
                    nearSinceAt = 0;
                    farSinceAt = 0;
                    lastUnlockAt = now;
                    ReconDumper.log("判定靠近 rssi=" + smooth + " 驻留=" + held + "ms");
                    ReconDumper.record("APPROACH rssi=" + smooth + " held=" + held + "ms");
                    fire("DOOR_UNLOCK", "靠近解锁");
                }
            } else {
                nearSinceAt = 0;
            }
        } else {
            if (smooth <= farThreshold) {
                if (farSinceAt == 0) {
                    farSinceAt = now;
                }
                if (now - farSinceAt >= farDwellMs && sinceLock >= lockCooldownMs) {
                    long held = now - farSinceAt;
                    present = false;
                    farSinceAt = 0;
                    nearSinceAt = 0;
                    lastLockAt = now;
                    ReconDumper.log("判定离开 rssi=" + smooth + " 驻留=" + held + "ms");
                    ReconDumper.record("DEPART rssi=" + smooth + " held=" + held + "ms");
                    fire("DOOR_LOCK", "远离锁车");
                }
            } else {
                farSinceAt = 0;
            }
        }
    }

    private static void fire(String type, String reason) {
        try {
            String r = DkBridge.sendBleCommand(type);
            ReconDumper.log(reason + " -> " + r);
            ReconDumper.record("FIRE " + type + " (" + reason + ") => " + r);
        } catch (Throwable t) {
            ReconDumper.log("下发失败 " + type + ": " + t);
        }
    }

    private static void lostCheck() {
        if (!running || !present) {
            return;
        }
        long now = System.currentTimeMillis();
        if (lastSeenAt > 0 && now - lastSeenAt > lostTimeoutMs
                && now - lastLockAt >= lockCooldownMs) {
            present = false;
            farSinceAt = 0;
            nearSinceAt = 0;
            lastLockAt = now;
            ReconDumper.log("目标丢失超时，判定离开");
            ReconDumper.record("DEPART_LOST");
            fire("DOOR_LOCK", "离开(信号丢失)");
        }
    }

    // ==================== 窗口 ====================

    private static void push(int v) {
        WIN[winPos] = v;
        winPos = (winPos + 1) % WIN_SIZE;
        if (winCount < WIN_SIZE) {
            winCount++;
        }
    }

    private static int median() {
        if (winCount == 0) {
            return 0;
        }
        int[] c = new int[winCount];
        System.arraycopy(WIN, 0, c, 0, winCount);
        Arrays.sort(c);
        return c[c.length / 2];
    }

    private static void reset() {
        winCount = 0;
        winPos = 0;
        present = false;
        nearSinceAt = 0;
        farSinceAt = 0;
        scanHitCount = 0;
        lastSeenAt = 0;
    }

    static String apiTag() {
        return "API" + Build.VERSION.SDK_INT;
    }
}
