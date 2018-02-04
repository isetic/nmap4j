package org.nmap4j;

import java.io.File;

public class NmapTestUtils {
    public static String findNmapPath() {
        String path = (new File("/usr/local/bin/nmap").exists()) ? "/usr/local" : "/usr";
        return path;
    }
}
