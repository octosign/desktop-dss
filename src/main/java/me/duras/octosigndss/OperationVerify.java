package me.duras.octosigndss;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.stream.Collectors;

import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.service.crl.OnlineCRLSource;
import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.service.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.client.http.IgnoreDataLoader;
import eu.europa.esig.dss.spi.tsl.TrustedListsCertificateSource;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.executor.ValidationLevel;
import eu.europa.esig.dss.validation.reports.Reports;
import me.duras.octosigndss.trust.IgnoreCrlSource;
import me.duras.octosigndss.trust.IgnoreOcspSource;
import me.duras.octosigndss.trust.LazyTLValidationJob;
import me.duras.octosigndss.trust.TrustLoader;

public class OperationVerify {
    public void run(String filePath) {
        if (!(filePath.endsWith(".pdf") || filePath.endsWith(".xml") || filePath.endsWith(".asice") || filePath.endsWith(".sce"))) {
            System.out.println("--RESULT--");
            System.out.println("UNKNOWN");
            System.out.println("--RESULT--");
            System.exit(0);
        }

        DSSDocument document = new FileDocument(filePath);

        // TODO: Find out how we can do this without using two document validators
        // See https://github.com/durasj/octosign-dss/issues/8
        Set<String> countries = getDocumentCertificateCountries(document);

        if (countries.size() == 0) {
            System.out.println("--RESULT--");
            System.out.println("UNSIGNED");
            System.out.println("--RESULT--");
            System.exit(0);
        }

        SignedDocumentValidator documentValidator = SignedDocumentValidator.fromDocument(document);

        CertificateVerifier cv = new CommonCertificateVerifier();
        // Capability to download resources from AIA
        cv.setDataLoader(new CommonsDataLoader());
        // Capability to request OCSP Responders
        cv.setOcspSource(new OnlineOCSPSource());
        // Capability to download CRL
        cv.setCrlSource(new OnlineCRLSource());
        // Use EU Trusted Certificate Lists
        cv.setTrustedCertSource(getTrustedCertificateSource(countries));
        documentValidator.setCertificateVerifier(cv);

        documentValidator.setValidationLevel(ValidationLevel.TIMESTAMPS);

        Reports reports = documentValidator.validateDocument();

        SimpleReport report = reports.getSimpleReport();
        String details = "";
        for (String id : report.getSignatureIdList()) {
            details += "### t{Signed by} " + report.getSignedBy(id) + "\n\n";
            details += "**t{Validity}**: t{" + getHumanReadableIndication(report.getIndication(id)) + "}\n\n";
            details += "**t{Date and time}**: " + report.getSigningTime(id) + "\n\n";
            details += "**t{Qualification}**: t{" + report.getSignatureQualification(id).getLabel() + "}\n\n";
            details += "**t{Chain of trust}**: " + report.getCertificateChain(id).getCertificate().stream()
                    .map((cert) -> cert.getQualifiedName()).collect(Collectors.joining(" > ")) + "\n\n";

            List<String> errors = report.getErrors(id);
            if (errors.size() > 0) {
                details += "**t{Potential problems}**: \n\n";
                int errorNumber = 1;
                for (String err : errors) {
                    details += errorNumber + ". " + err + "\n\n";
                    errorNumber++;
                }
            }

            details += "\n\n";
        }

        String status = "UNKNOWN";
        if (report.getSignaturesCount() == 0) {
            status = "UNSIGNED";
        } else if (report.getSignaturesCount() == report.getValidSignaturesCount()) {
            status = "SIGNED";
        } else if (report.getSignaturesCount() > report.getValidSignaturesCount()) {
            status = "INVALID";
        }

        System.out.println("--RESULT--");
        System.out.println(status);
        System.out.println(details);
        System.out.println("--RESULT--");
        System.exit(0);
    }

    private TrustedListsCertificateSource getTrustedCertificateSource(Set<String> requiredCountries) {
        TrustLoader loader = new TrustLoader();
        loader.load(requiredCountries);
        return loader.getTrustedCertificateSource();
    }

    private Set<String> getDocumentCertificateCountries(DSSDocument document) {
        SignedDocumentValidator documentValidator = SignedDocumentValidator.fromDocument(document);
        CertificateVerifier cv = new CommonCertificateVerifier();
        cv.setDataLoader(new IgnoreDataLoader());
        cv.setCrlSource(new IgnoreCrlSource());
        cv.setOcspSource(new IgnoreOcspSource());

        // Dummy certificate source just so that we can proceed
        cv.setTrustedCertSource(new TrustedListsCertificateSource());
        documentValidator.setCertificateVerifier(cv);

        Set<String> certificateCountries = new HashSet<String>();
        List<AdvancedSignature> signatures = documentValidator.getSignatures();
        for (AdvancedSignature signature : signatures) {
            List<CertificateToken> certificates = signature.getCertificateListWithinSignatureAndTimestamps();
            for (CertificateToken cert : certificates) {
                Matcher matcher = LazyTLValidationJob.canonicalizedCountryPattern
                        .matcher(cert.getCanonicalizedSubject());
                if (matcher.find())
                    certificateCountries.add(matcher.group(1));
            }
        }

        return certificateCountries;
    }

    private String getHumanReadableIndication(Indication indication) {
        switch (indication) {
            case TOTAL_PASSED:
            case PASSED:
                return "Valid";

            case TOTAL_FAILED:
            case FAILED:
                return "Invalid";

            case INDETERMINATE:
                return "Indeterminate";

            default:
                return "Unknown";
        }
    }
}
