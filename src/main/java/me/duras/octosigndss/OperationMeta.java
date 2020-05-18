package me.duras.octosigndss;

import java.io.File;
import java.util.Locale;

public class OperationMeta {
    public void run() {
        String pkcsDllPath = this.findPkcsDllPath();
        String defaultDllPath = pkcsDllPath == null ? "" : pkcsDllPath;

        System.out.println("--RESULT--");
        System.out.println("OK");
        System.out.println("OPTIONS:pkcsPath\"PKCS #11/#12 Path\"(\"" + defaultDllPath
                + "\") tspUrl\"Timestamping Server URL\"(\"http://timestamp.digicert.com\")");
        System.out.println("--RESULT--");
        System.exit(0);
    }

    private String findPkcsDllPath() {
        String[] windowsPkcsDlls = {
                // Slovak eID default installation directory
                "C:\\Program Files (x86)\\EAC MW klient\\pkcs11_x64.dll" };
        String[] linuxPkcsDlls = {
                // Slovak eID default installation directory
                "/usr/lib/eac_mw_klient/libpkcs11_x64.so" };
        String[] darwinPkcsDlls = {
                // Slovak eID default installation directory
                "/Applications/Aplikacia_pre_eID.app/Contents/pkcs11/libPkcs11.dylib" };

        String osName = System.getProperty("os.name", "generic").toLowerCase(Locale.ENGLISH);

        String[] paths;
        if ((osName.indexOf("mac") >= 0) || (osName.indexOf("darwin") >= 0)) {
            paths = darwinPkcsDlls;
        } else if (osName.indexOf("win") >= 0) {
            paths = windowsPkcsDlls;
        } else if (osName.indexOf("nux") >= 0) {
            paths = linuxPkcsDlls;
        } else {
            return null;
        }

        for (String path : paths) {
            if ((new File(path)).exists())
                return path;
        }

        return null;
    }
}