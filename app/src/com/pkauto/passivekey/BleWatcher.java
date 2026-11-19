package com.pkauto.passivekey;

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
import android.util.Log;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * BLE 靠近感知：扫描车机、平滑 RSSI、跑进入/离开状态机。
 *
 * 关键设计：
 *  - 定向模式使用 ScanFilter(deviceAddress)，因为 Android 对无过滤的后台扫描
 *    有每 30 分钟限流，而有过滤的扫描不受限，这是能长期后台工作的前提；
 *  - RSSI 用滑动窗口中位数，抑制多径与人体遮挡造成的尖峰；
 *  - 进入/离开都要求"连续 N 次"满足阈值，配合冷却时间防抖。
 */
public final class BleWatcher {

    private static final String TAG = "PK-Ble";

    public interface Listener {
        /** 判定为靠近（只触发一次） */
        void onApproach(int rssi);

        /** 判定为离开（只触发一次） */
        void onDepart(int rssi);

        /** 每次扫描到目标的原始/平滑值，用于 UI 与标定 */
        void onRssi(int rawRssi, int smoothRssi, String state);

        /** 诊断：扫描到的任意设备 */
        void onAnyDevice(String address, String name, int rssi);
    }

    // ---- 可调参数（由界面下发） ----
    /** 平滑后高于此值开始累计"靠近" */
    private int nearThreshold = -75;
    /** 平滑后低于此值开始累计"离开" */
    private int farThreshold = -82;
    /** 连续满足"靠近"多久触发解锁（毫秒，按真实时间而非采样次数） */
    private long nearDwellMs = 4500;
    /** 连续满足"离开"多久触发锁车（毫秒） */
    private long farDwellMs = 4500;
    /** 解锁后冷却，避免同一次上车反复下发 */
    private long unlockCooldownMs = 20000;
    /** 锁车后冷却 */
    private long lockCooldownMs = 15000;
    /** 目标消失多久算离开 */
    private long lostTimeoutMs = 45000;

    private static final int WIN_SIZE = 8;

    private enum State { AWAY, PRESENT }

    private final Context ctx;
    private final Listener listener;

    private BluetoothLeScanner scanner;
    private ScanCallback callback;

    private String targetMac;

    private final int[] win = new int[WIN_SIZE];
    private int winCount = 0;
    private int winPos = 0;

    private volatile State state = State.AWAY;
    /** 连续满足条件的起始时刻，0 表示当前不满足 */
    private long nearSinceAt = 0;
    private long farSinceAt = 0;
    private long lastUnlockAt = 0;
    private long lastLockAt = 0;
    private long lastSeenAt = 0;
    private int lastRaw = 0;
    private int lastSmooth = 0;

    private volatile boolean running = false;
    private volatile boolean diagnostic = false;

    public BleWatcher(Context ctx, Listener listener) {
        this.ctx = ctx.getApplicationContext();
        this.listener = listener;
    }

    public void setTargetMac(String mac) {
        this.targetMac = mac == null ? null : mac.trim().toUpperCase();
    }

    /** 驻留参数单位为毫秒 */
    public void setThresholds(int near, int far, int nearDwellMs, int farDwellMs) {
        this.nearThreshold = near;
        this.farThreshold = far;
        this.nearDwellMs = Math.max(200, nearDwellMs);
        this.farDwellMs = Math.max(200, farDwellMs);
    }

    public void setDiagnostic(boolean on) {
        this.diagnostic = on;
    }

    public String getStateName() {
        return state == State.PRESENT ? "PRESENT(车内/近场)" : "AWAY(远离)";
    }

    public void resetToAway() {
        state = State.AWAY;
        nearSinceAt = 0;
        farSinceAt = 0;
    }

    // ==================== 生命周期 ====================

    public boolean start() {
        if (running) {
            return true;
        }
        BluetoothManager bm =
                (BluetoothManager) ctx.getSystemService(Context.BLUETOOTH_SERVICE);
        if (bm == null) {
            Log.w(TAG, "无蓝牙服务");
            return false;
        }
        BluetoothAdapter adapter = bm.getAdapter();
        if (adapter == null || !adapter.isEnabled()) {
            Log.w(TAG, "蓝牙未开启");
            return false;
        }
        scanner = adapter.getBluetoothLeScanner();
        if (scanner == null) {
            Log.w(TAG, "无法获取 BLE 扫描器");
            return false;
        }

        callback = new ScanCallback() {
            @Override
            public void onScanResult(int callbackType, ScanResult result) {
                handleResult(result);
            }

            @Override
            public void onBatchScanResults(List<ScanResult> results) {
                if (results == null) {
                    return;
                }
                for (ScanResult r : results) {
                    handleResult(r);
                }
            }

            @Override
            public void onScanFailed(int errorCode) {
                Log.w(TAG, "扫描失败 errorCode=" + errorCode);
            }
        };

        List<ScanFilter> filters = new ArrayList<ScanFilter>();
        if (!diagnostic && targetMac != null && !targetMac.isEmpty()) {
            try {
                filters.add(new ScanFilter.Builder()
                        .setDeviceAddress(targetMac).build());
                Log.i(TAG, "定向扫描 MAC=" + targetMac);
            } catch (Throwable t) {
                Log.w(TAG, "构造 MAC 过滤失败: " + t);
            }
        }
        if (filters.isEmpty()) {
            Log.i(TAG, "无过滤扫描（诊断/未设 MAC），注意后台会被限流");
        }

        ScanSettings settings = new ScanSettings.Builder()
                .setScanMode(diagnostic
                        ? ScanSettings.SCAN_MODE_LOW_LATENCY
                        : ScanSettings.SCAN_MODE_LOW_LATENCY)
                .setReportDelay(0)
                .build();

        try {
            scanner.startScan(filters, settings, callback);
        } catch (Throwable t) {
            Log.w(TAG, "startScan 异常: " + t);
            return false;
        }
        running = true;
        // 冷启动一律从 AWAY 开始，避免刚启动就误判"已靠近"
        resetToAway();
        clearWindow();
        return true;
    }

    public void stop() {
        if (!running) {
            return;
        }
        running = false;
        try {
            if (scanner != null && callback != null) {
                scanner.stopScan(callback);
            }
        } catch (Throwable ignored) {
        }
        callback = null;
        scanner = null;
    }

    public boolean isRunning() {
        return running;
    }

    // ==================== 扫描结果处理 ====================

    private synchronized void handleResult(ScanResult result) {
        if (!running || result == null) {
            return;
        }
        BluetoothDevice dev = result.getDevice();
        if (dev == null) {
            return;
        }
        String addr = dev.getAddress();
        int rssi = result.getRssi();

        boolean isTarget;
        if (targetMac != null && !targetMac.isEmpty()) {
            isTarget = targetMac.equalsIgnoreCase(addr);
        } else {
            // 未指定目标时，诊断模式接受所有设备
            isTarget = true;
        }

        if (diagnostic && listener != null) {
            String name = null;
            try {
                name = dev.getName();
            } catch (Throwable ignored) {
            }
            listener.onAnyDevice(addr, name, rssi);
        }

        if (!isTarget) {
            return;
        }

        long now = System.currentTimeMillis();
        lastSeenAt = now;
        lastRaw = rssi;

        pushWindow(rssi);
        int smooth = median();
        lastSmooth = smooth;

        long sinceUnlock = now - lastUnlockAt;
        long sinceLock = now - lastLockAt;

        if (state == State.AWAY) {
            // 按真实时间累计，不受广播包频率影响
            if (smooth >= nearThreshold) {
                if (nearSinceAt == 0) {
                    nearSinceAt = now;
                }
                if (now - nearSinceAt >= nearDwellMs && sinceUnlock >= unlockCooldownMs) {
                    long held = now - nearSinceAt;
                    state = State.PRESENT;
                    nearSinceAt = 0;
                    farSinceAt = 0;
                    lastUnlockAt = now;
                    Log.i(TAG, "判定靠近 rssi=" + smooth + " 驻留=" + held + "ms");
                    if (listener != null) {
                        listener.onApproach(smooth);
                    }
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
                    state = State.AWAY;
                    farSinceAt = 0;
                    nearSinceAt = 0;
                    lastLockAt = now;
                    Log.i(TAG, "判定离开 rssi=" + smooth);
                    if (listener != null) {
                        listener.onDepart(smooth);
                    }
                }
            } else {
                farSinceAt = 0;
            }
        }

        if (listener != null) {
            listener.onRssi(lastRaw, smooth, getStateName());
        }
    }

    /** 定期检查"目标消失"，用于车机停止广播或人走远后无广播的情况 */
    public synchronized void tickLostCheck() {
        if (!running || state != State.PRESENT) {
            return;
        }
        long now = System.currentTimeMillis();
        if (lastSeenAt > 0 && now - lastSeenAt > lostTimeoutMs
                && now - lastLockAt >= lockCooldownMs) {
            state = State.AWAY;
            farSinceAt = 0;
            nearSinceAt = 0;
            lastLockAt = now;
            Log.i(TAG, "目标丢失超时，判定离开");
            if (listener != null) {
                listener.onDepart(lastSmooth);
            }
        }
    }

    // ==================== RSSI 窗口 ====================

    private void pushWindow(int v) {
        win[winPos] = v;
        winPos = (winPos + 1) % WIN_SIZE;
        if (winCount < WIN_SIZE) {
            winCount++;
        }
    }

    private void clearWindow() {
        winCount = 0;
        winPos = 0;
        Arrays.fill(win, 0);
    }

    private int median() {
        if (winCount == 0) {
            return 0;
        }
        int[] copy = new int[winCount];
        System.arraycopy(win, 0, copy, 0, winCount);
        Arrays.sort(copy);
        return copy[copy.length / 2];
    }

    // ==================== 静态工具 ====================

    /** 生成设备地址到名称的简易快照（诊断用） */
    public static Map<String, String> emptyDeviceMap() {
        return Collections.unmodifiableMap(new HashMap<String, String>());
    }

    public static boolean hasBleFeature(Context ctx) {
        return ctx.getPackageManager()
                .hasSystemFeature(android.content.pm.PackageManager.FEATURE_BLUETOOTH_LE);
    }

    public static String sdkTag() {
        return "API" + Build.VERSION.SDK_INT;
    }
}
