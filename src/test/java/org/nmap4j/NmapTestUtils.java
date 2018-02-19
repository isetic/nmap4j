package org.nmap4j;

import java.io.File;

public class NmapTestUtils {
	/**
	 * Nmap not allways located on same path, this method add locations to check.
	 */
	public static String findNmapPath() {
		String path = ( new File( "/usr/local/bin/nmap" ).exists() ) ? "/usr/local" : "/usr";
		return path;
	}
}
