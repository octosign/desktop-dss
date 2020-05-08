package me.duras.octosigndss.trust;

import eu.europa.esig.dss.spi.x509.revocation.ocsp.OfflineOCSPSource;

public class IgnoreOcspSource extends OfflineOCSPSource {
    private static final long serialVersionUID = 513234146189981356L;

    @Override
    public void appendContainedOCSPResponses() {
        // The point of this is to ignore all OCSP requests if we don't do a real validation
    }
}
