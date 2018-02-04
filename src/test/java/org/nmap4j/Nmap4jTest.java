package org.nmap4j;

import org.junit.Test;
import org.nmap4j.core.nmap.NMapExecutionException;
import org.nmap4j.core.nmap.NMapInitializationException;
import org.nmap4j.data.NMapRun;

import java.io.File;

import static org.junit.Assert.fail;

public class Nmap4jTest {


    @Test
    public void basicNmap4jUsageTest() throws NMapExecutionException, NMapInitializationException {


        String path = (new File("/usr/local/bin/nmap").exists()) ? "/usr/local" : "/usr";

        Nmap4j nmap4j = new Nmap4j(path);
        nmap4j.addFlags("-sV -T5 -oX -");
        nmap4j.includeHosts("localhost");
        nmap4j.execute();
        if (!nmap4j.hasError()) {
            NMapRun nmapRun = nmap4j.getResult();
            String output = nmap4j.getOutput();
            if (output == null) {
                fail();
            }
            String errors = nmap4j.getExecutionResults().getErrors();
            if (errors == null) {
                fail();
            }
        }


    }

}
