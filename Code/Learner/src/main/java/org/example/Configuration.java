package org.example;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Properties;

public class Configuration {
    private final Properties properties = new Properties();

    // Default configuration constant
    private static final String DEFAULT_PRO_NAME = "IoTStateFuzzer";
    private static final int DEFAULT_PORT = 9999;
    private static final String DEFAULT_OUTPUT_DIR = "result";
    private static final String DEFAULT_ALPHABET_FILE = "src/main/resources/input_bat";
    private static final int DEFAULT_VOTE_NUM = 3;
    private static final int DEFAULT_STATE_NUM = 7;
    private static final int DEFAULT_BASE_DEPTH = 1;
    private static final int DEFAULT_FUZZ_DEPTH = 2;

    // Configuration properties
    int port = DEFAULT_PORT;
    String outputDir = DEFAULT_OUTPUT_DIR;
    String cacheFile;
    String checkCacheFile;
    String statisticsFile;
    private String alphabetFile = DEFAULT_ALPHABET_FILE;
    boolean useCache = true;
    boolean useTimestamp = true;
    boolean useNoElement = true;
    boolean useKnowledge = true;
    boolean useHistory = true;
    boolean queryOut = true;
    int voteNum = DEFAULT_VOTE_NUM;
    int stateNum = DEFAULT_STATE_NUM;
    int baseDepth = DEFAULT_BASE_DEPTH;
    int fuzzDepth = DEFAULT_FUZZ_DEPTH;
    AlphabetManager aM;

    public Configuration(String confPath) throws IOException {
        try (InputStream input = Files.newInputStream(Paths.get(confPath))) {
            properties.load(input);
            loadProperties();
        } catch (IOException e) {
            LogManager.logger.error("Error loading configuration from file: " + confPath, e);
            throw e;
        }
    }

    // Load configuration information, or use the default configuration
    private void loadProperties() {
        // project name
        String proName = getPropertyOrDefault("proName", DEFAULT_PRO_NAME);
        LogManager.resetName(proName);
        LogManager.logger.logConfig("The project name: " + proName);

        // port
        port = Integer.parseInt(getPropertyOrDefault("port", String.valueOf(DEFAULT_PORT)));
        LogManager.logger.logConfig("The port: " + port);

        // output directory
        outputDir = getPropertyOrDefault("outputDir", DEFAULT_OUTPUT_DIR);
        LogManager.logger.logConfig("The output directory: " + outputDir);

        // useCache
        useCache = !"no".equalsIgnoreCase(properties.getProperty("useCache"));
        LogManager.logger.logConfig("The useCache: " + useCache);

        // cache file
        cacheFile = outputDir + "/" + getPropertyOrDefault("cacheFile", "cache.txt");
        LogManager.logger.logConfig("The cache file: " + cacheFile);

        // check cache file
        checkCacheFile = outputDir + "/" + getPropertyOrDefault("checkCacheFile", "cache_check.txt");
        LogManager.logger.logConfig("The check cache file: " + checkCacheFile);

        // alphabet file
        alphabetFile = getPropertyOrDefault("alphabetFile", DEFAULT_ALPHABET_FILE);
        if (setAlphabet()) {
            LogManager.logger.logConfig("Setting alphabet succeed!");
        } else {
            LogManager.logger.error("Failed to set alphabet");
        }
        LogManager.logger.logConfig("The alphabet file: " + alphabetFile);

        // depth of base model
        baseDepth = Integer.parseInt(getPropertyOrDefault("baseDepth", String.valueOf(DEFAULT_BASE_DEPTH)));
        LogManager.logger.logConfig("The depth of base model: " + baseDepth);

        // depth of state fuzzing model
        fuzzDepth = Integer.parseInt(getPropertyOrDefault("fuzzDepth", String.valueOf(DEFAULT_FUZZ_DEPTH)));
        LogManager.logger.logConfig("The depth of state fuzzing model: " + fuzzDepth);

        // number of votes
        voteNum = Integer.parseInt(getPropertyOrDefault("voteNum", String.valueOf(DEFAULT_VOTE_NUM)));
        LogManager.logger.logConfig("The number of votes: " + voteNum);

        // useTimestamp
        useTimestamp = !"no".equalsIgnoreCase(properties.getProperty("useTimestamp"));
        LogManager.logger.logConfig("The useTimestamp: " + useTimestamp);

        // useNoElement
        useNoElement = !"no".equalsIgnoreCase(properties.getProperty("useNoElement"));
        LogManager.logger.logConfig("The useNoElement: " + useNoElement);

        // statistics file
        statisticsFile = outputDir + "/" + getPropertyOrDefault("statisticsFile", "statistics.txt");
        LogManager.logger.logConfig("The statistics file: " + statisticsFile);

        // number of states
        stateNum = Integer.parseInt(getPropertyOrDefault("stateNum", String.valueOf(DEFAULT_STATE_NUM)));
        LogManager.logger.logConfig("The number of states: " + stateNum);

        // useKnowledge
        useKnowledge = !"no".equalsIgnoreCase(properties.getProperty("useKnowledge"));
        LogManager.logger.logConfig("The useKnowledge: " + useKnowledge);

        // queryOut
        queryOut = !"no".equalsIgnoreCase(properties.getProperty("queryOut"));
        LogManager.logger.logConfig("The queryOut: " + queryOut);

        // useHistory
        useHistory = !"no".equalsIgnoreCase(properties.getProperty("useHistory"));
        LogManager.logger.logConfig("The useHistory: " + useHistory);

        LogManager.logger.logConfig("Loading configuration succeeds");
    }

    // Reads the property value, using the default value if it is empty
    private String getPropertyOrDefault(String key, String defaultValue) {
        return properties.getProperty(key, defaultValue);
    }

    // Set alphabet
    public boolean setAlphabet() {
        File file = new File(alphabetFile);

        if (file.exists()) {
            aM = new AlphabetManager(alphabetFile);
            return true;
        } else {
            LogManager.logger.error("Alphabet file does not exist");
            return false;
        }
    }
}
