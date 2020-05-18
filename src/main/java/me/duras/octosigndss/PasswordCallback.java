package me.duras.octosigndss;

import eu.europa.esig.dss.token.PasswordInputCallback;

public class PasswordCallback implements PasswordInputCallback {
    Request request;

    public PasswordCallback(Request request) {
        this.request = request;
    }

    @Override
    public char[] getPassword() {
        String password = this.request.prompt("password", "Please provide the key password.", "");

        return password != null ? password.toCharArray() : "".toCharArray();
    }
}
