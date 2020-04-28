package me.duras.octosigndss;

import java.util.Map;
import java.util.Scanner;
import java.util.stream.Collectors;

public class Request {
    Scanner scanner;

    public Request(Scanner scanner) {
        this.scanner = scanner;
    }

    public String prompt(String promptType, String question, String defaultValue) {
        System.out.println("--PROMPT--");
        System.out.format("%s\"%s\"(\"%s\")\n", promptType, question, defaultValue);
        System.out.println("--PROMPT--");

        return this.handleAnswer("PROMPT");
    }

    public String prompt(String promptType, String question, String defaultValue, Map<String, String> options) {
        String preparedOptions = options.entrySet().stream()
            .map((entry) -> String.format("%s\"%s\"", entry.getKey(), entry.getValue()))
            .collect(Collectors.joining(" "));

        System.out.println("--PROMPT--");
        System.out.format("%s\"%s\"(\"%s\")[%s]\n", promptType, question, defaultValue, preparedOptions);
        System.out.println("--PROMPT--");

        return this.handleAnswer("PROMPT");
    }

    public String option(String id) {
        System.out.println("--GETOPTION--");
        System.out.println(id);
        System.out.println("--GETOPTION--");

        return this.handleAnswer("GETOPTION");
    }

    private String handleAnswer(String delimiter) {
        String answer = null;
        boolean isAnswer = false;
        while (scanner.hasNextLine()) {
            String line = scanner.nextLine().trim();

            if (isAnswer == true) {
                answer = line;
                isAnswer = false;
            }

            if (line.equals("--" + delimiter + "--") && answer == null) {
                isAnswer = true;
            }

            if (line.equals("--" + delimiter + "--") && answer != null) {
                break;
            }
        }

        return answer.isEmpty() ? null : answer;
    }
}