package net.sabamiso.android.revocationtest.crl;

class RevocationTestException extends Exception {
    public RevocationTestException(String msg) {
        super(msg);
    }

    public RevocationTestException(Exception e) {
        super(e);
    }
}
