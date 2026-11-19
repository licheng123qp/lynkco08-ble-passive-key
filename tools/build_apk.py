#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""手工构建 APK（aapt2 + javac + d8 + apksigner，不依赖 Gradle/AGP）。

用到的绝对路径都相对本文件推导，因此换机器只需保证 tools/ 下已解压 JDK 与 SDK。

用法：
    python tools/build_apk.py            # 构建 debug 签名版
"""
import os
import re
import shutil
import subprocess
import sys
import time
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOLS = os.path.join(ROOT, "tools")
JDK = os.path.join(TOOLS, "jdk")
SDK = os.path.join(TOOLS, "android-sdk")
BT = os.path.join(SDK, "build-tools", "34.0.0")
PLATFORM = os.path.join(SDK, "platforms", "android-34")
ANDROID_JAR = os.path.join(PLATFORM, "android.jar")

APP = os.path.join(ROOT, "app")
STUBS = os.path.join(ROOT, "stubs")
BUILD = os.path.join(ROOT, "build")
KEYS = os.path.join(TOOLS, "keys")
KEYSTORE = os.path.join(KEYS, "debug.jks")
OUT_APK = os.path.join(ROOT, "dist", "passivekey-debug.apk")

PKG = "com.pkauto.passivekey"


def env():
    e = dict(os.environ)
    e["JAVA_HOME"] = JDK
    e["PATH"] = os.path.join(JDK, "bin") + os.pathsep + e.get("PATH", "")
    return e


def run(cmd, desc, cwd=None, check=True):
    print(f"\n>>> {desc}")
    print("    " + " ".join(cmd) if isinstance(cmd, list) else "    " + cmd)
    p = subprocess.run(cmd, cwd=cwd, env=env(), shell=isinstance(cmd, str),
                       capture_output=True, text=True, errors="replace")
    out = (p.stdout or "") + (p.stderr or "")
    if out.strip():
        for line in out.strip().splitlines()[-25:]:
            print("    " + line)
    if check and p.returncode != 0:
        print(f"[!] 失败，退出码 {p.returncode}")
        sys.exit(p.returncode)
    return p


def collect_java(base):
    files = []
    for root, _dirs, fs in os.walk(base):
        for f in fs:
            if f.endswith(".java"):
                files.append(os.path.join(root, f))
    return sorted(files)


def class_files(base):
    files = []
    for root, _dirs, fs in os.walk(base):
        for f in fs:
            if f.endswith(".class"):
                files.append(os.path.join(root, f))
    return sorted(files)


def main():
    t0 = time.time()

    for need, path in (("JDK", os.path.join(JDK, "bin", "javac.exe")),
                       ("android.jar", ANDROID_JAR),
                       ("aapt2", os.path.join(BT, "aapt2.exe"))):
        if not os.path.exists(path):
            print(f"[!] 缺少 {need}: {path}")
            sys.exit(1)

    if os.path.isdir(BUILD):
        shutil.rmtree(BUILD)
    for d in ("res", "gen", "stubcls", "classes", "dex", "assets"):
        os.makedirs(os.path.join(BUILD, d), exist_ok=True)
    os.makedirs(os.path.join(ROOT, "dist"), exist_ok=True)

    # ---------- 0. 生成版本信息类 ----------
    stamp = time.strftime("%Y-%m-%d %H:%M")
    gen_src = os.path.join(BUILD, "gen", PKG.replace(".", "/"))
    os.makedirs(gen_src, exist_ok=True)
    with open(os.path.join(gen_src, "BuildConfigTime.java"), "w",
              encoding="utf-8") as f:
        f.write(f"package {PKG};\n\n"
                f"public final class BuildConfigTime {{\n"
                f"    public static final String VALUE = \"{stamp}\";\n"
                f"}}\n")

    # ---------- 1. 编译资源 ----------
    res_dir = os.path.join(APP, "res")
    flat_zip = os.path.join(BUILD, "res.zip")
    run([os.path.join(BT, "aapt2.exe"), "compile", "--dir", res_dir,
         "-o", flat_zip], "aapt2 compile")

    # ---------- 2. 生成 R.java 并链接资源 ----------
    assets_dir = os.path.join(APP, "assets")
    unsigned = os.path.join(BUILD, "unsigned.apk")
    run([os.path.join(BT, "aapt2.exe"), "link",
         "-o", unsigned,
         "-I", ANDROID_JAR,
         "--manifest", os.path.join(APP, "AndroidManifest.xml"),
         "-R", flat_zip,
         "-A", assets_dir,
         "--java", os.path.join(BUILD, "gen"),
         "--min-sdk-version", "29",
         "--target-sdk-version", "30",
         "--version-code", "1",
         "--version-name", "1.0",
         "--auto-add-overlay"],
        "aapt2 link")

    # ---------- 3. 编译 stub ----------
    stub_out = os.path.join(BUILD, "stubcls")
    stubs = collect_java(STUBS)
    run([os.path.join(JDK, "bin", "javac.exe"),
         "-encoding", "UTF-8", "-source", "8", "-target", "8",
         "-nowarn", "-d", stub_out,
         "-cp", ANDROID_JAR] + stubs,
        f"javac stubs ({len(stubs)})")

    # ---------- 4. 编译应用源码 ----------
    srcs = collect_java(os.path.join(APP, "src")) + collect_java(
        os.path.join(BUILD, "gen"))
    cls_out = os.path.join(BUILD, "classes")
    run([os.path.join(JDK, "bin", "javac.exe"),
         "-encoding", "UTF-8", "-source", "8", "-target", "8",
         "-nowarn", "-d", cls_out,
         "-bootclasspath", ANDROID_JAR,
         "-cp", os.pathsep.join([ANDROID_JAR, stub_out])] + srcs,
        f"javac app ({len(srcs)})")

    # ---------- 5. 转 dex（排除 stub） ----------
    dex_out = os.path.join(BUILD, "dex")
    classes = class_files(cls_out)
    d8_jar = os.path.join(BT, "lib", "d8.jar")
    run([os.path.join(JDK, "bin", "java.exe"), "-cp", d8_jar,
         "com.android.tools.r8.D8",
         "--release", "--min-api", "29",
         "--lib", ANDROID_JAR,
         "--output", dex_out] + classes,
        f"d8 -> classes.dex ({len(classes)} 个 class)")

    # ---------- 6. 装进 APK ----------
    # aapt2 link 已写入 manifest/res/assets，这里补 classes.dex
    dex_file = os.path.join(dex_out, "classes.dex")
    if not os.path.exists(dex_file):
        print("[!] 未生成 classes.dex")
        sys.exit(1)
    merged = os.path.join(BUILD, "merged.apk")
    with zipfile.ZipFile(unsigned, "r") as zin:
        names = set(zin.namelist())
        with zipfile.ZipFile(merged, "w", zipfile.ZIP_DEFLATED) as zout:
            for item in zin.infolist():
                zout.writestr(item, zin.read(item.filename))
            with open(dex_file, "rb") as f:
                zout.writestr("classes.dex", f.read())
    print(f"\n>>> 合并 APK: {sorted(names)[:8]} ... + classes.dex")

    # ---------- 7. 对齐 ----------
    aligned = os.path.join(BUILD, "aligned.apk")
    run([os.path.join(BT, "zipalign.exe"), "-f", "-p", "4",
         merged, aligned], "zipalign")

    # ---------- 8. 签名 ----------
    if not os.path.exists(KEYSTORE):
        os.makedirs(KEYS, exist_ok=True)
        run([os.path.join(JDK, "bin", "keytool.exe"),
             "-genkeypair", "-keystore", KEYSTORE,
             "-alias", "pk", "-keyalg", "RSA", "-keysize", "2048",
             "-validity", "10000",
             "-storepass", "android", "-keypass", "android",
             "-dname", "CN=PassiveKey, OU=Dev, O=PK, L=CN, ST=CN, C=CN"],
            "生成签名密钥")

    if os.path.exists(OUT_APK):
        os.remove(OUT_APK)
    run([os.path.join(JDK, "bin", "java.exe"),
         "-jar", os.path.join(BT, "lib", "apksigner.jar"),
         "sign",
         "--ks", KEYSTORE,
         "--ks-pass", "pass:android",
         "--key-pass", "pass:android",
         "--min-sdk-version", "29",
         "--out", OUT_APK, aligned],
        "apksigner sign")

    run([os.path.join(JDK, "bin", "java.exe"),
         "-jar", os.path.join(BT, "lib", "apksigner.jar"),
         "verify", "--print-certs", OUT_APK],
        "apksigner verify")

    size = os.path.getsize(OUT_APK)
    print(f"\n[OK] {OUT_APK}  ({size/1024:.1f} KB)  耗时 {time.time()-t0:.1f}s")


if __name__ == "__main__":
    main()
