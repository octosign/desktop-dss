package me.duras.octosigndss.trust;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;

/**
 * Simple wrapper that sets our own "proxy" for the get requests
 */
public class ProxiedCommonsDataLoader extends CommonsDataLoader {
    private static final long serialVersionUID = -906616344684206459L;

    private static final String PROXY_URL = "https://lotl-proxy.octosign.com/";

    @Override
    protected byte[] httpGet(String urlString) throws DSSException {
        return super.httpGet(PROXY_URL + "fetch?url=" + urlString);
    }
}
