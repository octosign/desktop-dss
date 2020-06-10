package me.duras.octosigndss;

import java.io.FileDescriptor;
import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.io.UnsupportedEncodingException;
import java.util.Scanner;

/**
 * DSS signing backend app
 */
public class App {
    static {
        // TODO: Temporary solution for PDFBox logging output
        // Ideally, we would use slf4j simpleLogger (via custom Log or LogFactory?)
        // https://github.com/durasj/octosign-dss/issues/10
        System.setProperty("org.apache.commons.logging.simplelog.defaultlog", "error");
    }

    public static void main(String[] args) throws UnsupportedEncodingException {
        Scanner scanner = new Scanner(new InputStreamReader(System.in, "UTF-8"));
        App.ensureUTF8SystemIO();

        if (args.length < 1) {
            System.err.println("One of the operations is required: sign, verify, meta.");
            System.exit(1);
        }

        if (args[0].equals("meta")) {
            (new OperationMeta()).run();
        } else if (args[0].equals("sign")) {
            (new OperationSign(scanner)).run(args[1]);
        } else if (args[0].equals("verify")) {
            (new OperationVerify()).run(args[1]);
        } else {
            System.err.println("Unsupported operation " + args[0]);
            System.exit(1);
        }
    }

    private static void ensureUTF8SystemIO() {
        try {
            System.setOut(new PrintStream(new FileOutputStream(FileDescriptor.out), true, "UTF-8"));
            System.setErr(new PrintStream(new FileOutputStream(FileDescriptor.err), true, "UTF-8"));
        } catch (UnsupportedEncodingException e) {
            throw new InternalError("VM does not support mandatory encoding UTF-8");
        }
    }
}
