package org.example;

import net.automatalib.alphabet.GrowingMapAlphabet;
import net.automatalib.automaton.transducer.MealyMachine;
import net.automatalib.serialization.dot.GraphDOT;

import java.io.*;
import java.sql.Timestamp;
import java.util.*;

public class Tool {
    public static void writeDotModel(MealyMachine<?, String, ?, String> model, GrowingMapAlphabet<String> alphabet, String filename) throws IOException {
        // Write output to dot-file
        File dotFile = new File(filename);
        PrintStream psDotFile = new PrintStream(dotFile);
        GraphDOT.write(model, alphabet, psDotFile);
        psDotFile.close();
        Runtime.getRuntime().exec("dot -Tpdf -O " + filename);

        LogManager.logger.logEvent("Write model: " + filename);
    }

    public static String getWinner(List<String> votes) {
        Map<String, Integer> voteCount = new HashMap<>();

        for (String vote : votes) {
            voteCount.put(vote, voteCount.getOrDefault(vote, 0) + 1);
        }

        String winner = null;
        int maxVotes = 0;

        for (Map.Entry<String, Integer> entry : voteCount.entrySet()) {
            if (entry.getValue() > maxVotes) {
                maxVotes = entry.getValue();
                winner = entry.getKey();
            }
        }

        return winner;
    }

    public static boolean compareLists(List<String> list1, List<String> list2) {
        if (list1 == null || list2 == null) {
            return false;
        }
        if (list1.size() != list2.size()) {
            return false;
        }
        for (int i = 0; i < list1.size(); i++) {
            if (!Objects.equals(list1.get(i), list2.get(i))) {
                return false;
            }
        }
        return true;
    }

    public static List<String> processVotes(List<String> symbol, NetworkManager network, int voteNum, boolean useNoElement) throws IOException {
        List<List<String>> results = new ArrayList<>();
        int m = symbol.size();
        for (int i = 0; i < voteNum; i++) {
            List<String> tmp = network.checkCounterExample(symbol, useNoElement);
            LogManager.logger.logEvent("Checking result " + (i + 1) + ": " + tmp);
            results.add(tmp);
        }
        List<String> result = new ArrayList<>();

        for (int i = 0; i < m; i++) {
            List<String> votes = new ArrayList<>();
            for (int j = 0; j < voteNum; j++) {
                votes.add(results.get(j).get(i));
            }

            String winner = getWinner(votes);
            result.add(winner);
        }

        return result;
    }

    public static boolean checkCounterexample(Configuration config, CacheManager cache, NetworkManager network) throws IOException {
        BufferedWriter writer = new BufferedWriter(new FileWriter(config.statisticsFile, true));
        LogManager.logger.logPhase("Check counterexample");

        writer.write("Check counterexample\n");
        writer.write("          start time: " + new Timestamp(System.currentTimeMillis()));
        writer.newLine();
        List<String> symbol, result, finalResult;
        symbol = new ArrayList<>(cache.getSymbol());
        result = new ArrayList<>(cache.getResult());
        Timestamp start = cache.getStart();
        cache.reloadCache();
        finalResult = processVotes(symbol, network, config.voteNum, config.useNoElement);
        writer.write("          finish time: " + new Timestamp(System.currentTimeMillis()));
        writer.newLine();
        if (compareLists(result, finalResult)) {
            cache.reloadCache(symbol, finalResult, start);
            LogManager.logger.logPhase("Current counterexample Pass the vote check to continue learning");
            LogManager.logger.logEvent("Final result: " + finalResult);
            writer.write("          result: success\n");
            writer.close();
            return true;
        } else {
            LogManager.logger.logPhase("Current counterexample fails the vote check and uses the cache to return to the previous state");
            writer.write("          result: failure\n");
            writer.close();
            return false;
        }
    }
}
