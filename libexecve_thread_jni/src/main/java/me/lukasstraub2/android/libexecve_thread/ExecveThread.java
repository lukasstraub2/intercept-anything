
package me.lukasstraub2.android.libexecve_thread;

import java.nio.charset.StandardCharsets;
import java.util.List;

public class ExecveThread {
    static {
        System.loadLibrary("execve_thread_jni");
    }

    private static native void execveThread(byte[] pathname, byte[][] argv);

    public static void execve(String _pathname, List<String> _argv) {
        int len = _argv.size();
        byte[] pathname = (_pathname + '\0').getBytes(StandardCharsets.UTF_8);
        byte[][] argv = new byte[len][];

        for (int i = 0; i < len; i++) {
            String _str = _argv.get(i);
            argv[i] = (_str + '\0').getBytes(StandardCharsets.UTF_8);
        }

        execveThread(pathname, argv);
    }
}
