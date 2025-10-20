package com.secure.notes.services;

import com.warrenstrange.googleauth.GoogleAuthenticatorKey;

public interface TotpService {
    GoogleAuthenticatorKey generateSecretKey();

    String getQRCodeURL(GoogleAuthenticatorKey secret, String username);

    boolean verifyCode(String secret, int code);
}
