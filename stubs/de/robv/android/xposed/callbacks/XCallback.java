package de.robv.android.xposed.callbacks;

public abstract class XCallback {
    public static class Param {
        public Object[] callbacks;
        public Object getObjectExtra(String key) { return null; }
        public void setObjectExtra(String key, Object o) { }
    }
}
