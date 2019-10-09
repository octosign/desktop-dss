package me.duras.octosigndss;

import eu.europa.esig.dss.token.PasswordInputCallback;

public class PasswordCallback implements PasswordInputCallback {

    @Override
    public char[] getPassword() {
        // TODO: Implement asking for a password

        return "TODO".toCharArray();
    }

}