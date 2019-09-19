package me.duras.octosigndss;

import java.io.File;
import java.io.IOException;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.service.tsp.OnlineTSPSource;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.Pkcs11SignatureToken;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;

/**
 * Hello world!
 *
 */
public class App {
    public static void main(String[] args) throws IOException {
        DSSDocument document = new FileDocument(new File("document.pdf"));

        // C:\\Program Files (x86)\\EAC MW klient\\pkcs11_x64.dll
        // /usr/lib/eac_mw_klient/libpkcs11_x64.so
        try (Pkcs11SignatureToken token = new Pkcs11SignatureToken(
                "C:\\Program Files (x86)\\EAC MW klient\\pkcs11_x64.dll", new PasswordCallback(), 1)) {

            DSSPrivateKeyEntry privateKey = token.getKeys().get(0);

            // Preparing parameters for the PAdES signature
            PAdESSignatureParameters parameters = new PAdESSignatureParameters();
            // We choose the level of the signature (-B, -T, -LT, -LTA).
            parameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_T);
            // We set the digest algorithm to use with the signature algorithm. You must use
            // the
            // same parameter when you invoke the method sign on the token. The default
            // value is
            // SHA256
            parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);

            // We set the signing certificate
            parameters.setSigningCertificate(privateKey.getCertificate());
            // We set the certificate chain
            parameters.setCertificateChain(privateKey.getCertificateChain());

            // Create common certificate verifier
            CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();
            // Create PAdESService for signature
            PAdESService service = new PAdESService(commonCertificateVerifier);

            // Create and set the TSP source
            OnlineTSPSource tspSource = new OnlineTSPSource("http://timestamp.digicert.com");
            service.setTspSource(tspSource);

            // Get the SignedInfo segment that need to be signed.
            ToBeSigned dataToSign = service.getDataToSign(document, parameters);

            // This function obtains the signature value for signed information using the
            // private key and specified algorithm
            DigestAlgorithm digestAlgorithm = parameters.getDigestAlgorithm();
            SignatureValue signatureValue = token.sign(dataToSign, digestAlgorithm, privateKey);

            // We invoke the PAdESService to sign the document with the signature value
            // obtained in
            // the previous step.
            DSSDocument signedDocument = service.signDocument(document, parameters, signatureValue);

            signedDocument.save("document-signed.pdf");
        }
    }
}
