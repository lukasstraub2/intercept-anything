package me.lukasstraub2.android.libexecve_thread;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

import java.util.Arrays;

class ExecveThreadTest {

    @Test
    public void testExecve() {
        String[] list = {"ls"};
        ExecveThread.execve("/bin/ls", Arrays.asList(list));
        try {
            Thread.sleep(1000);
        } catch (Exception e) {};
    }

}
