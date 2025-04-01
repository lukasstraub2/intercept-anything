package me.lukasstraub2.android.libexecve_thread;

import org.junit.Test;

import java.util.Arrays;

public class ExecveThreadTest {

    @Test
    public void testExecve() {
        String[] list = {"ls"};
        ExecveThread.execve("/bin/ls", Arrays.asList(list));
        try {
            Thread.sleep(1000);
        } catch (Exception e) {};
    }

}
