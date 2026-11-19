package com.pkauto.passivekey;

import android.Manifest;
import android.app.Activity;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothManager;
import android.bluetooth.le.BluetoothLeScanner;
import android.bluetooth.le.ScanCallback;
import android.bluetooth.le.ScanResult;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.graphics.Typeface;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.provider.Settings;
import android.text.InputType;
import android.text.TextUtils;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * 主界面：权限、启动、状态、标定与联调入口。
 */
public class MainActivity extends Activity {

    private Prefs prefs;
    private TextView tvStatus;
    private TextView tvEvents;
    private EditText etMac;
    private EditText etNear;
    private EditText etFar;
    private EditText etDwell;
    private Button btnStart;

    private final Handler ui = new Handler(Looper.getMainLooper());
    private final ExecutorService worker = Executors.newSingleThreadExecutor();

    private BluetoothLeScanner diagScanner;
    private ScanCallback diagCallback;
    private final Map<String, Integer> diagSeen = new LinkedHashMap<String, Integer>();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        prefs = new Prefs(this);
        setContentView(buildUi());
        ensurePermissions();
    }

    // ==================== UI ====================

    private View buildUi() {
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(dp(16), dp(20), dp(16), dp(16));

        TextView title = new TextView(this);
        title.setText("领克无感钥匙");
        title.setTextSize(22f);
        title.setTypeface(Typeface.DEFAULT_BOLD);
        root.addView(title);

        TextView sub = new TextView(this);
        sub.setText("构建 " + BuildConfigTime.VALUE
                + "  ·  " + BleWatcher.sdkTag());
        sub.setTextSize(11f);
        sub.setTextColor(Color.GRAY);
        root.addView(sub);

        tvStatus = new TextView(this);
        tvStatus.setTextSize(13f);
        tvStatus.setPadding(0, dp(10), 0, dp(8));
        tvStatus.setText("状态加载中…");
        root.addView(tvStatus);

        // MAC 输入
        LinearLayout macRow = new LinearLayout(this);
        macRow.setOrientation(LinearLayout.HORIZONTAL);
        macRow.setGravity(Gravity.CENTER_VERTICAL);

        etMac = new EditText(this);
        etMac.setHint("车机 BLE MAC，如 AA:BB:CC:DD:EE:FF");
        etMac.setTextSize(12f);
        etMac.setInputType(InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
        String mac = prefs.mac();
        if (mac == null || mac.isEmpty()) {
            mac = prefs.macHint();
        }
        etMac.setText(mac);
        macRow.addView(etMac, new LinearLayout.LayoutParams(0,
                ViewGroup.LayoutParams.WRAP_CONTENT, 1f));

        Button btnSave = mkBtn("保存");
        btnSave.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                prefs.setMac(etMac.getText().toString());
                toast("已保存 MAC");
                if (PassiveKeyService.running) {
                    toast("请重启服务生效");
                }
            }
        });
        macRow.addView(btnSave);
        root.addView(macRow);

        // 距离参数（车边现场微调，改完立即下发到模块，无需重启）
        TextView tuneLabel = new TextView(this);
        tuneLabel.setText("距离参数（依次：解锁 dBm / 上锁 dBm / 驻留 s）");
        tuneLabel.setTextSize(11f);
        tuneLabel.setTextColor(Color.GRAY);
        tuneLabel.setPadding(0, dp(10), 0, 0);
        root.addView(tuneLabel);

        LinearLayout tuneRow = new LinearLayout(this);
        tuneRow.setOrientation(LinearLayout.HORIZONTAL);
        tuneRow.setGravity(Gravity.CENTER_VERTICAL);
        tuneRow.setPadding(0, dp(6), 0, 0);

        LinearLayout.LayoutParams oneThird = new LinearLayout.LayoutParams(
                0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
        etNear = mkNum("近 dBm");
        etFar = mkNum("远 dBm");
        etDwell = mkNum("驻留 s");
        etNear.setText(String.valueOf(prefs.near()));
        etFar.setText(String.valueOf(prefs.far()));
        etDwell.setText(secText(prefs.nearDwellMs()));
        tuneRow.addView(etNear, oneThird);

        LinearLayout.LayoutParams oneThird2 = new LinearLayout.LayoutParams(
                0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
        oneThird2.leftMargin = dp(6);
        tuneRow.addView(etFar, oneThird2);

        LinearLayout.LayoutParams oneThird3 = new LinearLayout.LayoutParams(
                0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
        oneThird3.leftMargin = dp(6);
        tuneRow.addView(etDwell, oneThird3);

        Button btnTune = mkBtn("应用");
        btnTune.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                applyTune();
            }
        });
        tuneRow.addView(btnTune);
        root.addView(tuneRow);

        // 主按钮
        btnStart = mkBtn("启动无感");
        btnStart.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if (PassiveKeyService.running) {
                    PassiveKeyService.stop(MainActivity.this);
                    prefs.setEnabled(false);
                    toast("已请求停止");
                } else {
                    prefs.setEnabled(true);
                    PassiveKeyService.start(MainActivity.this);
                    toast("已启动");
                }
                ui.postDelayed(refresh, 800);
            }
        });
        root.addView(btnStart);

        // 联调按钮
        root.addView(group("联调（需模块已注入官方 APP）",
                new String[]{"PING", "STATUS", "ENUMS",
                        "UNLOCK", "LOCK", "DOOR",
                        "SCAN", "RESULT", "WSTATE"},
                new String[]{"PING", "STATUS", "ENUMS",
                        "UNLOCK", "LOCK", "DOOR",
                        "SCANALL", "SCANRESULT", "WSTATE"}));

        // 诊断
        Button btnDiag = mkBtn("扫描周围 BLE 设备（找车机 MAC）");
        btnDiag.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                startDiag();
            }
        });
        root.addView(btnDiag);

        Button btnSetting = mkBtn("打开系统设置（省电/自启动）");
        btnSetting.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                try {
                    startActivity(new Intent(
                            Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
                            android.net.Uri.parse("package:" + getPackageName())));
                } catch (Throwable t) {
                    toast("打开失败");
                }
            }
        });
        root.addView(btnSetting);

        tvEvents = new TextView(this);
        tvEvents.setTextSize(11f);
        tvEvents.setTypeface(Typeface.MONOSPACE);
        tvEvents.setPadding(0, dp(12), 0, 0);

        ScrollView sv = new ScrollView(this);
        sv.addView(tvEvents);
        root.addView(sv, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));

        return root;
    }

    private LinearLayout group(String label, String[] texts, final String[] cmds) {
        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setPadding(0, dp(8), 0, 0);

        TextView t = new TextView(this);
        t.setText(label);
        t.setTextSize(11f);
        t.setTextColor(Color.GRAY);
        box.addView(t);

        // 均分一行时每个按钮只有 ~55dp，小于系统 Button 的 minWidth，
        // 文字会被折行导致高度不一致。改为固定列数的网格 + 单行按钮。
        final int cols = 3;
        LinearLayout row = null;
        for (int i = 0; i < texts.length; i++) {
            if (i % cols == 0) {
                row = new LinearLayout(this);
                row.setOrientation(LinearLayout.HORIZONTAL);
                LinearLayout.LayoutParams rlp = new LinearLayout.LayoutParams(
                        ViewGroup.LayoutParams.MATCH_PARENT,
                        ViewGroup.LayoutParams.WRAP_CONTENT);
                if (i > 0) {
                    rlp.topMargin = dp(6);
                }
                box.addView(row, rlp);
            }
            final String cmd = cmds[i];
            Button b = mkSmallBtn(texts[i]);
            b.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    runBridge(cmd);
                }
            });
            LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                    0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
            if (i % cols != 0) {
                lp.leftMargin = dp(6);
            }
            row.addView(b, lp);
        }
        return box;
    }

    /** 网格里用的小按钮：去掉系统最小尺寸、强制单行，保证高度一致 */
    private Button mkSmallBtn(String text) {
        Button b = new Button(this);
        b.setText(text);
        b.setAllCaps(false);
        b.setTextSize(12f);
        b.setSingleLine(true);
        b.setEllipsize(TextUtils.TruncateAt.END);
        b.setIncludeFontPadding(false);
        b.setMinWidth(0);
        b.setMinimumWidth(0);
        b.setMinHeight(0);
        b.setMinimumHeight(0);
        b.setPadding(dp(6), dp(9), dp(6), dp(9));
        b.setGravity(Gravity.CENTER);
        return b;
    }

    private Button mkBtn(String text) {
        Button b = new Button(this);
        b.setText(text);
        b.setAllCaps(false);
        b.setTextSize(13f);
        return b;
    }

    private void runBridge(final String cmd) {
        worker.execute(new Runnable() {
            @Override
            public void run() {
                final String r = BridgeClient.send(MainActivity.this, cmd);
                ui.post(new Runnable() {
                    @Override
                    public void run() {
                        addLocalLine(cmd + " → " + r);
                    }
                });
            }
        });
    }

    /** 数字输入框（窄，居中，供三个参数并排使用） */
    private EditText mkNum(String hint) {
        EditText e = new EditText(this);
        e.setHint(hint);
        e.setTextSize(12f);
        e.setGravity(Gravity.CENTER);
        e.setSingleLine(true);
        e.setInputType(InputType.TYPE_CLASS_NUMBER
                | InputType.TYPE_NUMBER_FLAG_SIGNED
                | InputType.TYPE_NUMBER_FLAG_DECIMAL);
        e.setPadding(dp(4), dp(6), dp(4), dp(6));
        return e;
    }

    /** 毫秒转展示用的秒文本，4.5s 显示 4.5，3000ms 显示 3 */
    private static String secText(int ms) {
        float v = ms / 1000f;
        if (Math.abs(v - Math.round(v)) < 0.01f) {
            return String.valueOf(Math.round(v));
        }
        return String.format(java.util.Locale.US, "%.1f", v);
    }

    /** 校验并保存距离参数，同时热更新到官方 APP 进程内的感知层 */
    private void applyTune() {
        int near;
        int far;
        int dwellMs;
        try {
            near = Integer.parseInt(etNear.getText().toString().trim());
            far = Integer.parseInt(etFar.getText().toString().trim());
            dwellMs = Math.round(
                    Float.parseFloat(etDwell.getText().toString().trim()) * 1000f);
        } catch (Throwable t) {
            toast("请填数字，例如 -75 / -82 / 4.5");
            return;
        }
        if (near > 0 || far > 0) {
            toast("dBm 是负值，例如 -75 / -82");
            return;
        }
        if (near <= far) {
            toast("近阈值需大于远阈值（近 -75 > 远 -82）");
            return;
        }
        if (dwellMs < 200 || dwellMs > 60000) {
            toast("驻留需在 0.2 ~ 60 秒之间");
            return;
        }
        prefs.setThresholds(near, far, dwellMs, dwellMs);
        addLocalLine("参数已保存: 近≥" + near + " 远≤" + far
                + " 驻留=" + secText(dwellMs) + "s");
        ui.post(refresh);

        final String cfg = "CONFIG " + near + "," + far + "," + dwellMs + "," + dwellMs;
        worker.execute(new Runnable() {
            @Override
            public void run() {
                final String r = BridgeClient.send(MainActivity.this, cfg);
                ui.post(new Runnable() {
                    @Override
                    public void run() {
                        addLocalLine("参数下发 → " + r);
                    }
                });
            }
        });
    }


    // ==================== 状态刷新 ====================

    private final Runnable refresh = new Runnable() {
        @Override
        public void run() {
            StringBuilder sb = new StringBuilder();
            sb.append("服务: ").append(PassiveKeyService.running ? "运行中" : "已停止").append("\n");
            sb.append("感知: ").append(PassiveKeyService.stateText).append("\n");
            sb.append("RSSI: 原始 ").append(PassiveKeyService.lastRawRssi)
                    .append(" dBm / 平滑 ").append(PassiveKeyService.lastSmoothRssi)
                    .append(" dBm\n");
            sb.append("阈值: 近 ≥").append(prefs.near())
                    .append(" dBm / 远 ≤").append(prefs.far()).append(" dBm")
                    .append(" / 驻留 ").append(secText(prefs.nearDwellMs())).append("s")
                    .append("\n");
            sb.append("目标 MAC: ").append(
                    empty(prefs.mac()) ? "未设置" : prefs.mac()).append("\n");
            sb.append("桥接: ").append(
                    empty(PassiveKeyService.bridgeInfo)
                            ? "未知" : PassiveKeyService.bridgeInfo);
            tvStatus.setText(sb.toString());

            btnStart.setText(PassiveKeyService.running ? "停止无感" : "启动无感");

            StringBuilder ev = new StringBuilder();
            synchronized (PassiveKeyService.EVENTS) {
                for (String s : PassiveKeyService.EVENTS) {
                    ev.append(s).append("\n");
                }
            }
            ev.append(localBuf);
            tvEvents.setText(ev.toString());

            ui.postDelayed(this, 1000);
        }
    };

    private String localBuf = "";

    private void addLocalLine(String s) {
        java.text.SimpleDateFormat f =
                new java.text.SimpleDateFormat("HH:mm:ss", java.util.Locale.US);
        localBuf = f.format(new java.util.Date()) + "  " + s + "\n" + localBuf;
        if (localBuf.length() > 4000) {
            localBuf = localBuf.substring(0, 4000);
        }
    }

    @Override
    protected void onResume() {
        super.onResume();
        ui.post(refresh);
    }

    @Override
    protected void onPause() {
        super.onPause();
        ui.removeCallbacks(refresh);
        stopDiag();
    }

    // ==================== 诊断扫描 ====================

    private void startDiag() {
        if (!hasBlePerms()) {
            toast("缺少蓝牙权限");
            return;
        }
        BluetoothManager bm =
                (BluetoothManager) getSystemService(Context.BLUETOOTH_SERVICE);
        BluetoothAdapter ad = bm == null ? null : bm.getAdapter();
        if (ad == null || !ad.isEnabled()) {
            toast("请先打开蓝牙");
            return;
        }
        diagScanner = ad.getBluetoothLeScanner();
        if (diagScanner == null) {
            toast("无法扫描");
            return;
        }
        diagSeen.clear();
        diagCallback = new ScanCallback() {
            @Override
            public void onScanResult(int type, ScanResult result) {
                if (result == null || result.getDevice() == null) {
                    return;
                }
                String addr = result.getDevice().getAddress();
                String name = null;
                try {
                    name = result.getDevice().getName();
                } catch (Throwable ignored) {
                }
                String key = addr + (name == null || name.isEmpty() ? "" : "  " + name);
                diagSeen.put(key, result.getRssi());
            }
        };
        try {
            diagScanner.startScan(diagCallback);
            toast("扫描 8 秒…");
            ui.postDelayed(new Runnable() {
                @Override
                public void run() {
                    stopDiag();
                }
            }, 8000);
        } catch (Throwable t) {
            toast("扫描失败: " + t.getMessage());
        }
    }

    private void stopDiag() {
        if (diagScanner != null && diagCallback != null) {
            try {
                diagScanner.stopScan(diagCallback);
            } catch (Throwable ignored) {
            }
        }
        diagScanner = null;
        diagCallback = null;
        if (diagSeen.isEmpty()) {
            return;
        }
        StringBuilder sb = new StringBuilder("扫描结果:\n");
        for (Map.Entry<String, Integer> e : diagSeen.entrySet()) {
            sb.append("  ").append(e.getKey()).append("  ").append(e.getValue())
                    .append(" dBm\n");
        }
        addLocalLine(sb.toString());
        diagSeen.clear();
    }

    // ==================== 权限 ====================

    private boolean hasBlePerms() {
        if (Build.VERSION.SDK_INT >= 31) {
            return checkSelfPermission(Manifest.permission.BLUETOOTH_SCAN)
                    == PackageManager.PERMISSION_GRANTED
                    && checkSelfPermission(Manifest.permission.BLUETOOTH_CONNECT)
                    == PackageManager.PERMISSION_GRANTED;
        }
        return checkSelfPermission(Manifest.permission.ACCESS_FINE_LOCATION)
                == PackageManager.PERMISSION_GRANTED;
    }

    private void ensurePermissions() {
        if (Build.VERSION.SDK_INT >= 31) {
            requestPermissions(new String[]{
                    Manifest.permission.BLUETOOTH_SCAN,
                    Manifest.permission.BLUETOOTH_CONNECT,
                    Manifest.permission.ACCESS_FINE_LOCATION,
                    Manifest.permission.POST_NOTIFICATIONS,
            }, 1001);
        } else {
            requestPermissions(new String[]{
                    Manifest.permission.ACCESS_FINE_LOCATION,
                    Manifest.permission.POST_NOTIFICATIONS,
            }, 1002);
        }
    }

    // ==================== 小工具 ====================

    private int dp(int v) {
        return Math.round(getResources().getDisplayMetrics().density * v);
    }

    private void toast(String s) {
        Toast.makeText(this, s, Toast.LENGTH_SHORT).show();
    }

    private static boolean empty(String s) {
        return s == null || s.trim().isEmpty();
    }
}
