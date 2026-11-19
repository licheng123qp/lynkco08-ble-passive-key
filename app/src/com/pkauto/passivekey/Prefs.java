package com.pkauto.passivekey;

import android.content.Context;
import android.content.SharedPreferences;

/** 本地配置。默认值针对领克 08 的实测起点。 */
public final class Prefs {

    private static final String FILE = "passivekey";

    public static final String K_ENABLED = "enabled";
    public static final String K_MAC = "target_mac";
    public static final String K_NEAR = "near_threshold";
    public static final String K_FAR = "far_threshold";
    /** 驻留改为毫秒（旧版本是秒且按采样计数，故意换 key 避免误读旧值） */
    public static final String K_NEAR_DWELL = "near_dwell_ms";
    public static final String K_FAR_DWELL = "far_dwell_ms";
    public static final String K_AUTO_UNLOCK = "auto_unlock";
    public static final String K_AUTO_LOCK = "auto_lock";

    /** 已从官方 APP 侧获知的车机 MAC（首次运行时自动填入） */
    public static final String K_MAC_HINT = "mac_hint";

    private final SharedPreferences sp;

    public Prefs(Context ctx) {
        sp = ctx.getApplicationContext()
                .getSharedPreferences(FILE, Context.MODE_PRIVATE);
    }

    public boolean enabled() {
        return sp.getBoolean(K_ENABLED, false);
    }

    public void setEnabled(boolean v) {
        sp.edit().putBoolean(K_ENABLED, v).apply();
    }

    public String mac() {
        return sp.getString(K_MAC, "");
    }

    public void setMac(String v) {
        sp.edit().putString(K_MAC, v == null ? "" : v.trim().toUpperCase()).apply();
    }

    public void setMacHint(String v) {
        sp.edit().putString(K_MAC_HINT, v == null ? "" : v).apply();
    }

    public String macHint() {
        return sp.getString(K_MAC_HINT, "");
    }

    /** 平滑 RSSI ≥ 此值算"在车边" */
    public int near() {
        return sp.getInt(K_NEAR, -75);
    }

    /** 平滑 RSSI ≤ 此值算"已走远" */
    public int far() {
        return sp.getInt(K_FAR, -82);
    }

    /** 连续满足"靠近"多久才解锁（毫秒） */
    public int nearDwellMs() {
        return sp.getInt(K_NEAR_DWELL, 4500);
    }

    /** 连续满足"走远"多久才锁车（毫秒） */
    public int farDwellMs() {
        return sp.getInt(K_FAR_DWELL, 4500);
    }

    /** 参数单位为毫秒 */
    public void setThresholds(int near, int far, int nearDwellMs, int farDwellMs) {
        sp.edit().putInt(K_NEAR, near).putInt(K_FAR, far)
                .putInt(K_NEAR_DWELL, nearDwellMs)
                .putInt(K_FAR_DWELL, farDwellMs).apply();
    }

    public boolean autoUnlock() {
        return sp.getBoolean(K_AUTO_UNLOCK, true);
    }

    public boolean autoLock() {
        return sp.getBoolean(K_AUTO_LOCK, true);
    }

    public void setAuto(boolean unlock, boolean lock) {
        sp.edit().putBoolean(K_AUTO_UNLOCK, unlock)
                .putBoolean(K_AUTO_LOCK, lock).apply();
    }
}
