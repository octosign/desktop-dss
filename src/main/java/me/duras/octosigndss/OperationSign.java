package me.duras.octosigndss;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.text.SimpleDateFormat;
import java.util.HashMap;
import java.util.List;
import java.util.Scanner;

import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;

import eu.europa.esig.dss.AbstractSignatureParameters;
import eu.europa.esig.dss.asic.cades.ASiCWithCAdESSignatureParameters;
import eu.europa.esig.dss.asic.cades.signature.ASiCWithCAdESService;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.service.tsp.OnlineTSPSource;
import eu.europa.esig.dss.signature.AbstractSignatureService;
import eu.europa.esig.dss.token.AbstractKeyStoreTokenConnection;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.Pkcs11SignatureToken;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;

public class OperationSign {
    private Scanner scanner;

    public OperationSign(Scanner scanner) {
        this.scanner = scanner;
    }

    public void run(String filePath) {
        Request request = new Request(scanner);
        String pkcsDllPath = request.option("dllPath");
        String tspUrl = request.option("tspUrl");

        if (pkcsDllPath == null) {
            System.err.println("PKCS #11 library path is not configured. Please check Settings and Help.");
            System.exit(1);
        }

        if (!Files.exists(Paths.get(pkcsDllPath))) {
            System.err.println("PKCS #11 library doesn't exist. Please check Settings and Help.");
            System.exit(1);
        }

        if (tspUrl == null) {
            System.err.println("Timestamping server URL is not configured.");
            System.exit(1);
        }

        File fileToSign = new File(filePath);
        DSSDocument document = new FileDocument(fileToSign);

        // TODO: Try different slots and give a choice if more than one works
        try (Pkcs11SignatureToken token = new Pkcs11SignatureToken(pkcsDllPath, new PasswordCallback(request), 1)) {
            DSSPrivateKeyEntry privateKey = this.getPrivateKey(request, token);

            // Create common certificate verifier
            // TODO: Add trust for -LT/-LTA in the future
            CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();

            AbstractSignatureService service = null;
            AbstractSignatureParameters parameters = null;
            if (fileToSign.getName().endsWith(".pdf")) {
                parameters = new PAdESSignatureParameters();
                // We choose the level of the signature (-B, -T, -LT, -LTA).
                parameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_T);
                parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
                parameters.setSigningCertificate(privateKey.getCertificate());
                parameters.setCertificateChain(privateKey.getCertificateChain());

                service = new PAdESService(commonCertificateVerifier);
            } else if (fileToSign.getName().endsWith(".xml")) {
                parameters = new XAdESSignatureParameters();
                // We choose the level of the signature (-B, -T, -LT, -LTA).
                parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_T);
                parameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);
                parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
                parameters.setSigningCertificate(privateKey.getCertificate());
                parameters.setCertificateChain(privateKey.getCertificateChain());

                service = new XAdESService(commonCertificateVerifier);
            } else {
                ASiCWithCAdESSignatureParameters asicParameters = new ASiCWithCAdESSignatureParameters();
                // We choose the level of the signature (-B, -T, -LT, -LTA).
                asicParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_T);
                asicParameters.aSiC().setContainerType(ASiCContainerType.ASiC_E);
                asicParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
                asicParameters.setSigningCertificate(privateKey.getCertificate());
                asicParameters.setCertificateChain(privateKey.getCertificateChain());
                parameters = asicParameters;

                service = new ASiCWithCAdESService(commonCertificateVerifier);
            }

            // Create and set the TSP source
            OnlineTSPSource tspSource = new OnlineTSPSource(tspUrl);
            service.setTspSource(tspSource);

            // Get the SignedInfo segment that need to be signed.
            ToBeSigned dataToSign = service.getDataToSign(document, parameters);

            // This function obtains the signature value for signed information using the
            // private key and specified algorithm
            DigestAlgorithm digestAlgorithm = parameters.getDigestAlgorithm();
            SignatureValue signatureValue = token.sign(dataToSign, digestAlgorithm, privateKey);

            // We invoke the PAdESService to sign the document with the signature value
            // obtained in the previous step.
            DSSDocument signedDocument = service.signDocument(document, parameters, signatureValue);

            String path = request.prompt("save", "Save signed file as", fileToSign.getAbsolutePath());

            if (path == null) {
                System.err.println("Signed file path was not chosen.");
                System.exit(1);
            }

            // Make sure file extension is correct
            if (parameters instanceof ASiCWithCAdESSignatureParameters
                    && !(path.endsWith(".sce") || path.endsWith(".asice"))) {
                path += ".sce";
            } else if (fileToSign.getName().endsWith(".pdf") && !path.endsWith(".pdf")) {
                path += ".pdf";
            } else if (fileToSign.getName().endsWith(".xml") && !path.endsWith(".xml")) {
                path += ".xml";
            }

            try {
                signedDocument.save(path);
            } catch (Exception e) {
                System.err.println("There was an error saving the signed document.");
                System.exit(1);
            }

            System.out.println("--RESULT--");
            System.out.println(path);
            System.out.println("--RESULT--");
            System.exit(0);
        } catch (Exception e) {
            System.err.println("Using of the PKCS #11 library failed.");
            System.exit(1);
        }
    }

    private DSSPrivateKeyEntry getPrivateKey(Request request, AbstractKeyStoreTokenConnection token) {
        List<DSSPrivateKeyEntry> keys;
        try {
            keys = token.getKeys();
        } catch (Exception e) {
            System.err.println("Communication with device failed.");
            System.exit(1);
            return null;
        }

        // Automatically choose for the user if only one is available
        if (keys.size() == 1) {
            return keys.get(0);
        }

        HashMap<String, String> keyOptions = new HashMap<String, String>();
        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd");
        for (DSSPrivateKeyEntry key : keys) {
            String dn = key.getCertificate().getSubjectX500Principal().getName("RFC2253");
            String label = "";
            try {
                LdapName ldapDN = new LdapName(dn);
                String dnName = "";
                String dnCountry = "";
                String dnCity = "";
                String dnStreet = "";
                String notBefore = dateFormat.format(key.getCertificate().getNotBefore());
                String notAfter = dateFormat.format(key.getCertificate().getNotAfter());
                for (Rdn rdn : ldapDN.getRdns()) {
                    if (rdn.getType().equalsIgnoreCase("CN"))
                        dnName = rdn.getValue().toString();
                    if (rdn.getType().equalsIgnoreCase("C"))
                        dnCountry = rdn.getValue().toString();
                    if (rdn.getType().equalsIgnoreCase("L"))
                        dnCity = rdn.getValue().toString();
                    if (rdn.getType().equalsIgnoreCase("STREET"))
                        dnStreet = rdn.getValue().toString();
                }

                label = String.format("%s, %s %s, %s (%s - %s)", dnName, dnCity, dnStreet, dnCountry, notBefore,
                        notAfter);
            } catch (Exception e) {
                label = "Certificate SN: " + key.getCertificate().getCertificate().getSerialNumber().toString(16);
            }

            keyOptions.put(key.getCertificate().getDSSId().asXmlId(), label);
        }
        String chosenKey = request.prompt("single", "Please pick a certificate for signing", "", keyOptions);
        if (chosenKey == null) {
            System.err.println("Certificate was not chosen.");
            System.exit(1);
        }

        DSSPrivateKeyEntry privateKey = keys.stream()
                .filter(key -> chosenKey.equals(key.getCertificate().getDSSId().asXmlId())).findAny().orElse(null);

        if (privateKey == null) {
            System.err.println("Certificate was not chosen.");
            System.exit(1);
        }

        return privateKey;
    }
}
