#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""生成 Xposed API 编译期 stub。

这些类仅用于 javac 编译通过，不会被打包进 APK —— 运行期由 LSPosed 框架
（bootclasspath 上的 libxposed）提供真实实现。方法签名必须与真实 API 一致。
"""
import os

OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                   "stubs")

FILES = {}

FILES["de/robv/android/xposed/IXposedHookLoadPackage.java"] = """\
package de.robv.android.xposed;

import de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam;

public interface IXposedHookLoadPackage {
    void handleLoadPackage(LoadPackageParam lpparam) throws Throwable;
}
"""

FILES["de/robv/android/xposed/IXposedHookZygoteInit.java"] = """\
package de.robv.android.xposed;

public interface IXposedHookZygoteInit {
    void initZygote(StartupParam startupParam) throws Throwable;

    class StartupParam {
        public String modulePath;
        public boolean startsSystemServer;
    }
}
"""

FILES["de/robv/android/xposed/callbacks/XCallback.java"] = """\
package de.robv.android.xposed.callbacks;

public abstract class XCallback {
    public static class Param {
        public Object[] callbacks;
        public Object getObjectExtra(String key) { return null; }
        public void setObjectExtra(String key, Object o) { }
    }
}
"""

FILES["de/robv/android/xposed/callbacks/XC_LoadPackage.java"] = """\
package de.robv.android.xposed.callbacks;

import android.content.pm.ApplicationInfo;

public class XC_LoadPackage extends XCallback {
    public static class LoadPackageParam extends XCallback.Param {
        public String packageName;
        public String processName;
        public ClassLoader classLoader;
        public ApplicationInfo appInfo;
        public boolean isFirstApplication;
    }
}
"""

FILES["de/robv/android/xposed/XC_MethodHook.java"] = """\
package de.robv.android.xposed;

import java.lang.reflect.Member;

public abstract class XC_MethodHook {
    public XC_MethodHook() { }
    public XC_MethodHook(int priority) { }

    protected void beforeHookedMethod(MethodHookParam param) throws Throwable { }
    protected void afterHookedMethod(MethodHookParam param) throws Throwable { }

    public static class MethodHookParam extends de.robv.android.xposed.callbacks.XCallback.Param {
        public Member method;
        public Object thisObject;
        public Object[] args;
        private Object result;
        private Throwable throwable;

        public Object getResult() { return result; }
        public void setResult(Object result) { this.result = result; }
        public Throwable getThrowable() { return throwable; }
        public void setThrowable(Throwable throwable) { this.throwable = throwable; }
        public boolean hasThrowable() { return throwable != null; }
        public Object getResultOrThrowable() throws Throwable {
            if (throwable != null) throw throwable;
            return result;
        }
    }

    public class Unhook {
        public XC_MethodHook getCallback() { return XC_MethodHook.this; }
        public void unhook() { }
    }
}
"""

FILES["de/robv/android/xposed/XC_MethodReplacement.java"] = """\
package de.robv.android.xposed;

public abstract class XC_MethodReplacement extends XC_MethodHook {
    public XC_MethodReplacement() { super(); }
    public XC_MethodReplacement(int priority) { super(priority); }

    protected abstract Object replaceHookedMethod(MethodHookParam param) throws Throwable;

    @Override
    protected final void beforeHookedMethod(MethodHookParam param) throws Throwable {
        try {
            param.setResult(replaceHookedMethod(param));
        } catch (Throwable t) {
            param.setThrowable(t);
        }
    }

    public static XC_MethodReplacement returnConstant(final Object result) {
        return new XC_MethodReplacement() {
            @Override
            protected Object replaceHookedMethod(MethodHookParam param) {
                return result;
            }
        };
    }

    public static XC_MethodReplacement doNothing() {
        return returnConstant(null);
    }
}
"""

FILES["de/robv/android/xposed/XposedBridge.java"] = """\
package de.robv.android.xposed;

import java.lang.reflect.Member;
import java.util.HashSet;
import java.util.Set;

public final class XposedBridge {
    private XposedBridge() { }

    public static void log(String text) { }
    public static void log(Throwable t) { }

    public static XC_MethodHook.Unhook hookMethod(Member hookMethod,
                                                  XC_MethodHook callback) {
        return null;
    }

    public static Set<XC_MethodHook.Unhook> hookAllMethods(
            Class<?> hookClass, String methodName, XC_MethodHook callback) {
        return new HashSet<XC_MethodHook.Unhook>();
    }

    public static Set<XC_MethodHook.Unhook> hookAllConstructors(
            Class<?> hookClass, XC_MethodHook callback) {
        return new HashSet<XC_MethodHook.Unhook>();
    }
}
"""

FILES["de/robv/android/xposed/XposedHelpers.java"] = """\
package de.robv.android.xposed;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;

public final class XposedHelpers {
    private XposedHelpers() { }

    public static Class<?> findClass(String className, ClassLoader classLoader) {
        return null;
    }

    public static Class<?> findClassIfExists(String className, ClassLoader classLoader) {
        return null;
    }

    public static Field findField(Class<?> clazz, String fieldName) { return null; }
    public static Field findFieldIfExists(Class<?> clazz, String fieldName) { return null; }
    public static Method findMethodExact(Class<?> clazz, String methodName,
                                         Object... parameterTypes) { return null; }
    public static Method findMethodExactIfExists(Class<?> clazz, String methodName,
                                                 Object... parameterTypes) { return null; }
    public static Constructor<?> findConstructorExact(Class<?> clazz,
                                                      Object... parameterTypes) { return null; }

    public static Object getObjectField(Object obj, String fieldName) { return null; }
    public static Object getStaticObjectField(Class<?> clazz, String fieldName) { return null; }
    public static void setObjectField(Object obj, String fieldName, Object value) { }
    public static void setStaticObjectField(Class<?> clazz, String fieldName, Object value) { }
    public static int getIntField(Object obj, String fieldName) { return 0; }
    public static void setIntField(Object obj, String fieldName, int value) { }
    public static boolean getBooleanField(Object obj, String fieldName) { return false; }

    public static Object callMethod(Object obj, String methodName, Object... args) { return null; }
    public static Object callStaticMethod(Class<?> clazz, String methodName,
                                          Object... args) { return null; }
    public static Object newInstance(Class<?> clazz, Object... args) { return null; }

    public static Object callMethod(Object obj, String methodName,
                                    Class<?>[] parameterTypes, Object... args) { return null; }
    public static Object callStaticMethod(Class<?> clazz, String methodName,
                                          Class<?>[] parameterTypes, Object... args) { return null; }
}
"""


def main():
    for rel, content in FILES.items():
        p = os.path.join(OUT, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            f.write(content)
        print("[+] " + rel)
    print(f"\n共 {len(FILES)} 个 stub 类 -> {OUT}")


if __name__ == "__main__":
    main()
