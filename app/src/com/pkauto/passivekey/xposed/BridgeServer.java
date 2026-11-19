package com.pkauto.passivekey.xposed;

import android.net.LocalServerSocket;
import android.net.LocalSocket;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.charset.Charset;

/**
 * 桥接服务端：跑在官方 APP 进程内，接受自研 APP 的指令并转成内部 API 调用。
 *
 * 通信：Android 抽象命名空间 LocalSocket，协议为行文本
 *   请求           响应
 *   PING        -> PONG
 *   STATUS      -> STATUS dkId=<masked> conn=<...>
 *   UNLOCK      -> OK <detail>     （BLE DOOR_UNLOCK）
 *   LOCK        -> OK <detail>     （BLE DOOR_LOCK）
 *   APPROACH_ON -> OK <detail>     （打开靠近解锁开关）
 *   APPROACH_OFF-> OK <detail>
 *   WALKAWAY_ON -> OK <detail>
 *   WALKAWAY_OFF-> OK <detail>
 *   DOOR        -> OK <detail>     （高层 controlDoor，降级用）
 */
final class BridgeServer {

    static final String SOCKET_NAME = "pk_bridge";
    private static final Charset UTF8 = Charset.forName("UTF-8");

    private static volatile boolean running = false;
    private static LocalServerSocket server;

    private BridgeServer() {
    }

    static synchronized void start(ClassLoader cl) {
        if (running) {
            return;
        }
        running = true;
        DkBridge.init(cl);

        Thread t = new Thread(new Runnable() {
            @Override
            public void run() {
                loop();
            }
        }, "pk-bridge");
        t.setDaemon(true);
        t.start();
        ReconDumper.log("BridgeServer 启动，socket=" + SOCKET_NAME);
    }

    private static void loop() {
        while (running) {
            try {
                if (server == null) {
                    server = new LocalServerSocket(SOCKET_NAME);
                    ReconDumper.log("BridgeServer 已监听");
                }
                final LocalSocket client = server.accept();
                Thread h = new Thread(new Runnable() {
                    @Override
                    public void run() {
                        handle(client);
                    }
                }, "pk-bridge-conn");
                h.setDaemon(true);
                h.start();
            } catch (Throwable t) {
                String msg = String.valueOf(t.getMessage());
                if (msg != null && msg.contains("Address already in use")) {
                    // 主进程与 dkservice 进程会同时尝试监听同名 socket，
                    // 后到的直接停用即可（广播通道才是主通道）。
                    ReconDumper.log("socket 已被另一进程占用，本进程仅用广播通道");
                    running = false;
                    closeQuietly();
                    return;
                }
                ReconDumper.log("BridgeServer accept 异常: " + t);
                closeQuietly();
                sleep(2000);
            }
        }
    }

    private static void handle(LocalSocket sock) {
        String peer = "?";
        try {
            peer = String.valueOf(sock.getRemoteSocketAddress());
            BufferedReader in = new BufferedReader(
                    new InputStreamReader(sock.getInputStream(), UTF8));
            OutputStream out = sock.getOutputStream();

            String line;
            while ((line = in.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty()) {
                    continue;
                }
                String resp = dispatch(line);
                out.write((resp + "\n").getBytes(UTF8));
                out.flush();
            }
        } catch (Throwable t) {
            ReconDumper.log("BridgeServer 连接结束 (" + peer + "): " + t);
        } finally {
            try {
                sock.close();
            } catch (Throwable ignored) {
            }
        }
    }

    private static String dispatch(String cmd) {
        ReconDumper.record("CMD " + cmd);
        try {
            if ("PING".equals(cmd)) {
                return "PONG " + DkBridge.mask(DkBridge.getDkId());
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
            if (cmd.startsWith("SETDKID ")) {
                DkBridge.learnDkId(cmd.substring(8).trim());
                return "OK dkId=" + DkBridge.mask(DkBridge.getDkId());
            }
            if ("ENUMS".equals(cmd)) {
                return "BleControlType=" + DkBridge.enumNames(DkBridge.CLS_BLE_CONTROL_TYPE)
                        + " CmdChannel=" + DkBridge.enumNames(DkBridge.CLS_CMD_CHANNEL);
            }
            return "ERR unknown command";
        } catch (Throwable t) {
            ReconDumper.record("CMD_FAIL " + cmd + " : " + t);
            return "ERR " + t.getClass().getSimpleName() + ": " + t.getMessage();
        }
    }

    private static void closeQuietly() {
        try {
            if (server != null) {
                server.close();
            }
        } catch (Throwable ignored) {
        } finally {
            server = null;
        }
    }

    private static void sleep(long ms) {
        try {
            Thread.sleep(ms);
        } catch (InterruptedException ignored) {
        }
    }
}
