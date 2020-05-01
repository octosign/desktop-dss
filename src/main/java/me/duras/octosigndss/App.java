package me.duras.octosigndss;

import java.io.FileDescriptor;
import java.io.FileOutputStream;
import java.io.PrintStream;
import java.io.UnsupportedEncodingException;
import java.util.Scanner;

/**
 * DSS signing backend app
 */
public class App {
    private static Scanner scanner = new Scanner(System.in);

    public static void main(String[] args) {
        App.ensureUTF8SystemOut();

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

    private static void ensureUTF8SystemOut() {
        try {
            System.setOut(new PrintStream(new FileOutputStream(FileDescriptor.out), true, "UTF-8"));
        } catch (UnsupportedEncodingException e) {
            throw new InternalError("VM does not support mandatory encoding UTF-8");
        }
    }
}
