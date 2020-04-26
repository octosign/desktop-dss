package me.duras.octosigndss;

import java.io.File;
import java.io.IOException;
import java.util.Locale;
import java.util.Scanner;

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
 * DSS signing backend app
 */
public class App {
    private static Scanner scanner = new Scanner(System.in);

    public static void main(String[] args) throws IOException {
        if (args.length < 1) {
            System.err.println("One of the operations is required: sign, verify, meta.");
            System.exit(1);
        }

        if (args[0].equals("meta")) {
            App.meta();
        } else if (args[0].equals("sign")) {
            App.sign(args[1]);
        } else if (args[0].equals("verify")) {
            System.err.println("Verify operation is not yet supported");
            System.exit(1);
        } else {
            System.err.println("Unsupported operation " + args[0]);
            System.exit(1);
        }
    }

    private static void meta() {
        String pkcsDllPath = App.findPkcsDllPath();

        System.out.println("--RESULT--");
        if (pkcsDllPath == null) {
            System.out.println("Autoconfiguration failed. Check Settings and Help.");
        } else {
            System.out.println("OK");
        }

        String defaultDllPath = pkcsDllPath == null ? "" : pkcsDllPath;
        System.out.println("SUPPORTS:application/pdf");
        System.out.println("OPTIONS:dllPath\"PKCS #11 Library Path\"(\"" + defaultDllPath
                + "\") tspUrl\"Timestamping Server URL\"(\"http://timestamp.digicert.com\")");
        System.out.println("--RESULT--");
        System.exit(0);
    }

    private static void sign(String filePath) throws IOException {
        String pkcsDllPath = App.option("dllPath");
        String tspUrl = App.option("tspUrl");

        if (pkcsDllPath == null) {
            System.err.println("PKCS #11 library path is not configured.");
            System.exit(1);
        }

        if (tspUrl == null) {
            System.err.println("Timestamping server URL is not configured.");
            System.exit(1);
        }

        File fileToSign = new File(filePath);
        DSSDocument document = new FileDocument(fileToSign);

        try (Pkcs11SignatureToken token = new Pkcs11SignatureToken(pkcsDllPath, new PasswordCallback(), 1)) {

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
            OnlineTSPSource tspSource = new OnlineTSPSource(tspUrl);
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

            signedDocument.save(fileToSign.getAbsolutePath().replace(".pdf", "-signed.pdf"));
        }
        System.exit(0);
    }

    private static String prompt(String promptType, String question, String defaultValue) {
        System.out.println("--PROMPT--");
        System.out.format("%s\"%s\"(\"%s\")\n", promptType, question, defaultValue);
        System.out.println("--PROMPT--");

        String answer = null;
        boolean isAnswer = false;
        while (scanner.hasNextLine()){
            String line = scanner.nextLine().trim();

            if (isAnswer == true) {
                answer = line;
            }

            if (line.equals("--PROMPT--") && answer == null) {
                isAnswer = true;
            }

            if (line.equals("--PROMPT--") && answer != null) {
                break;
            }
        }

        return answer.isEmpty() ? null : answer;
    }

    private static String option(String id) {
        System.out.println("--GETOPTION--");
        System.out.println(id);
        System.out.println("--GETOPTION--");

        String answer = null;
        boolean isAnswer = false;
        while (scanner.hasNextLine()) {
            String line = scanner.nextLine().trim();

            System.out.println("GOT: " + line);

            if (isAnswer == true) {
                answer = line;
                isAnswer = false;
            }

            if (line.equals("--GETOPTION--") && answer == null) {
                isAnswer = true;
            }

            if (line.equals("--GETOPTION--") && answer != null) {
                break;
            }
        }

        System.out.println("ANSWER IS:" + answer);

        return answer.isEmpty() ? null : answer;
    }

    private static String findPkcsDllPath() {
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
