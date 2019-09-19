package me.duras.octosigndss;

import eu.europa.esig.dss.token.PasswordInputCallback;

public class PasswordCallback implements PasswordInputCallback {

    @Override
    public char[] getPassword() {
        System.out.println("Getting password");

        return "123".toCharArray();
    }

}