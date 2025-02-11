package org.example;

import java.io.*;
import java.util.*;
import java.sql.Timestamp;

import static org.example.AlphabetManager.*;

public class CacheManager {
    private static String cachePath = null;

    private final List<String> symbol, result;
    private final List<Timestamp> start, end;

    private List<String> cacheResults;

    private int index = 0;
    private int resetNum = 0;

    public CacheManager(String fileName) {
        LogManager.logger.logEvent("Initialize the Cache manager....");
        cachePath = fileName;
        this.resetNum = loadCache();
        LogManager.logger.logEvent("Number of resets in the current cache: " + resetNum);
        this.symbol = new ArrayList<>();
        this.result = new ArrayList<>();
        this.start = new ArrayList<>();
        this.end = new ArrayList<>();
    }

    public void reconfigure(String newFile) {
        LogManager.logger.logEvent("Reconfigure the Cache manager....");
        cachePath = newFile;
        this.resetNum = loadCache();
        LogManager.logger.logEvent("Number of resets in the current cache: " + resetNum);
        clearAll();
    }

    public List<String> getSymbol() {
        return symbol;
    }

    public List<String> getResult() {
        return result;
    }

    public int getResetNum() {
        return resetNum;
    }

    public int getIndex() {
        return index;
    }

    private void addReset(Timestamp start, Timestamp end) {
        symbol.add(RESET_SYMBOL);
        result.add(RESET_RESULT);
        this.start.add(start);
        this.end.add(end);
        resetNum++;
        // LogManager.logger.logEvent("resetNum: " + resetNum);
    }


    public void restartCache() {
//        LogManager.logger.logEvent("Returns the cache read counter to initial");
        index = 0;
    }

    private int loadCache() {
        int resetLineCount = 0;
        cacheResults = new ArrayList<>();

        try (BufferedReader reader = new BufferedReader(new FileReader(cachePath))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String[] parts = line.split(",");
                if (parts.length == 4 || parts.length == 2) {
                    if (Objects.equals(parts[1], RESET_SYMBOL) || Objects.equals(parts[0], RESET_SYMBOL)) {
                        resetLineCount++;
                    } else {
                        cacheResults.add(parts[parts.length - 1]);
                    }
                }
            }
        } catch (IOException e) {
            LogManager.logger.error(String.valueOf(e));
        }
        return resetLineCount;
    }

    public void add(String symbol, String result) {
        this.symbol.add(symbol);
        this.result.add(result);
    }

    public void add(String symbol, String result, Timestamp start, Timestamp end) {
        this.symbol.add(symbol);
        this.result.add(result);
        this.start.add(start);
        this.end.add(end);
    }

    private void clearAll() {
        this.symbol.clear();
        this.result.clear();
        this.start.clear();
        this.end.clear();
    }

    public void writeCacheWithoutTime() {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(cachePath, true))) {
            for (int i = 0; i < Math.min(this.symbol.size(), this.result.size()); i++) {
                String line = this.symbol.get(i) + "," + this.result.get(i);
                writer.write(line);
                writer.newLine();
            }
        } catch (IOException e) {
            LogManager.logger.error(String.valueOf(e));
        }

        this.symbol.clear();
        this.result.clear();
    }

    // Write the results of the round query to the file
    private void writeCacheWithTime() {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(cachePath, true))) {
            for (int i = 0; i < Math.min(this.symbol.size(), this.result.size()); i++) {
                String line = this.start.get(i) + "," + this.symbol.get(i) + ","
                        + this.end.get(i) + "," + this.result.get(i);
                writer.write(line);
                writer.newLine();
            }
        } catch (IOException e) {
            LogManager.logger.error(String.valueOf(e));
        }
        clearAll();
    }

    public void writeCacheInReset(Timestamp start, Timestamp end) {
        writeCacheWithTime();
        addReset(start, end);
    }

    public void writeCacheForFinish() {
        writeCacheWithTime();
    }

    public void writeCacheForVote(Timestamp start, Timestamp end) {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(cachePath, true))) {
            for (int i = 0; i < Math.min(this.symbol.size(), this.result.size()); i++) {
                String line = start + "," + this.symbol.get(i) + ","
                        + end + "," + this.result.get(i);
                writer.write(line);
                writer.newLine();
            }
        } catch (IOException e) {
            LogManager.logger.error(String.valueOf(e));
        }
        clearAll();
    }

    // Record query when using cache
    public String get(String symbol) {
        String result = cacheResults.get(index++);
        if (result.startsWith(symbol) || result.equals(RESTRICTED_SYMBOL))
            return result;
        return "Wrong";
    }

    public void reloadCache() {
//        LogManager.logger.logEvent("Clear the sequence in the current cache variable");
        clearAll();
        resetNum = loadCache();
        LogManager.logger.logEvent("Number of resets after the cache is reloaded: " + resetNum);
    }

    // After the vote is successful, write the result to the file
    public void reloadCache(List<String> symbol, List<String> result, Timestamp start) {
        LogManager.logger.logEvent("After the vote is successful, write the result to the file");
        clearAll();

        this.result.addAll(result);
        this.symbol.addAll(symbol);

        writeCacheForVote(start, new Timestamp(System.currentTimeMillis()));
        resetNum = loadCache();
        LogManager.logger.logEvent("Number of resets after the cache is reloaded: " + resetNum);
    }

    // Gets the start time of the current query
    public Timestamp getStart() {
        LogManager.logger.logEvent("Get the start time of the current query");
        return start.get(0);
    }
}
