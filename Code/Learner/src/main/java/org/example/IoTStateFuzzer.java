package org.example;

import java.io.IOException;

// Learner program launch portal
public class IoTStateFuzzer {
    // Configuration file relative path
    static final String confPath = "src/main/resources/conf.properties";

    public static void main(String[] args) throws IOException {
        try {
            // Load Configuration
            Configuration conf = new Configuration(confPath);

            // Building Sockets for Communication
            NetworkManager network = new NetworkManager(conf.port);

            // Set new alphabet
            conf.setAlphabet();

            // Set cache query for learner
            CacheManager cache = new CacheManager(conf.cacheFile);

            // Build a learner
            Learner learner= new Learner(conf, network, cache);

            // learn base state machine
            learner.learn("base_model");

            // State fuzzing
            learner.stateFuzz();

        } catch (IOException e) {
            // Handle IO Exception
            LogManager.logger.error(e.toString());
        }
    }
}