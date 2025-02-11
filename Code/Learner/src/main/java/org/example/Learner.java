package org.example;

import de.learnlib.acex.AcexAnalyzers;
import de.learnlib.algorithm.ttt.base.TTTState;
import de.learnlib.algorithm.ttt.base.TTTTransition;
import de.learnlib.algorithm.ttt.mealy.TTTLearnerMealy;
import de.learnlib.filter.cache.sul.SULCaches;
import de.learnlib.filter.statistic.Counter;
import de.learnlib.filter.statistic.sul.ResetCounterSUL;
import de.learnlib.oracle.EquivalenceOracle;
import de.learnlib.oracle.equivalence.*;
import de.learnlib.oracle.membership.SULOracle;
import de.learnlib.query.DefaultQuery;
import de.learnlib.statistic.StatisticSUL;
import de.learnlib.sul.SUL;
import de.learnlib.util.statistic.SimpleProfiler;
import net.automatalib.alphabet.GrowingMapAlphabet;
import net.automatalib.automaton.transducer.MealyMachine;
import net.automatalib.word.Word;

import java.io.*;
import java.sql.Timestamp;
import java.util.*;

public class Learner {
    public static final int BASE_MODEL = 0;
    public static final int STATE_FUZZ = 1;
    private static final int LEARNING_STAGE = 0;
    private static final int EQUIVALENCE_STAGE = 1;

    private final GrowingMapAlphabet<String> alphabet;
    private final Configuration config;
    private final Mediator mediator;
    private final NetworkManager network;
    private final CacheManager cache;

    private static int stage;
    private static int writeNum;
    private static int roundNum;

    private Counter round;
    private int restartNum;
    private int lastConflictNum;
    private int learningStage;
    private DefaultQuery<String, Word<String>> counterExample;
    private StatisticSUL<String, String> statisticMqSul;
    private StatisticSUL<String, String> statisticEqSul;
    private TTTLearnerMealy<String, String> learningOracle;
    private EquivalenceOracle.MealyEquivalenceOracle<String, String> equivalenceOracle;
    private MealyMachine<TTTState<String, String>, String, TTTTransition<String, String>, String> hypothesis;

    public Learner(Configuration config, NetworkManager network, CacheManager cache) {
        this.config = config;
        this.network = network;
        this.cache = cache;

        mediator = new Mediator(this.config, this.network, this.cache);
        alphabet = mediator.getAlphabet();
        stage = BASE_MODEL;

        start();
    }

    public static int getStage() {
        return stage;
    }

    public static int getWriteNum() {
        return writeNum;
    }

    public static int getRoundNum() {
        return roundNum;
    }

    private void loadLearningAlgorithm() {
        statisticMqSul = new ResetCounterSUL<>("membership queries", mediator);
        SUL<String, String> effectiveMqSul = SULCaches.createCache(alphabet, statisticMqSul);
        SULOracle<String, String> mqOracle = new SULOracle<>(effectiveMqSul);
        learningOracle = new TTTLearnerMealy<>(alphabet, mqOracle, AcexAnalyzers.LINEAR_FWD);

//        if (writeNum == 0)
//            LogManager.logger.logEvent("Learning algorithm (TTT) initialization complete");
    }


    private void loadEquivalenceAlgorithm() {
        statisticEqSul = new ResetCounterSUL<>("equivalence queries", mediator);
        SUL<String, String> effectiveEqSul = SULCaches.createCache(alphabet, statisticEqSul);
        SULOracle<String, String> eqOracle = new SULOracle<>(effectiveEqSul);
        int depth;
        if (stage == BASE_MODEL)
            depth = config.baseDepth;
        else
            depth = config.fuzzDepth;

        // Wp-Method
        equivalenceOracle = new MealyWpMethodEQOracle<>(eqOracle, depth);

//        if (writeNum == 0)
//            LogManager.logger.logEvent("Equivalence oracle (WpMethod) initialization complete");
    }

    private void loadLearnerAlgo() {
        loadLearningAlgorithm();
        loadEquivalenceAlgorithm();
    }

    private void start() {
        restartNum = 0;
        lastConflictNum = 0;
        writeNum = roundNum = 0;
        loadLearnerAlgo();
    }

    private void reLearn() {
//        LogManager.logger.logEvent("Restart learning and return to the position where the error occurred");
        lastConflictNum = cache.getIndex();
        cache.restartCache();
        mediator.restartMediator();
        loadLearnerAlgo();
    }

    private void getHypothesis() {
        if (roundNum == 0)
            round = new Counter("Rounds", "");
        round.increment();
        LogManager.logger.logPhase("Starting round " + round.getCount());
        // Marks the current phase, which is used to select a resolution strategy when a conflict occurs
        learningStage = LEARNING_STAGE;
        SimpleProfiler.start("Learning");
        if (roundNum == 0)
            learningOracle.startLearning();
        else
            learningOracle.refineHypothesis(counterExample);
        SimpleProfiler.stop("Learning");

        hypothesis = (MealyMachine<TTTState<String, String>, String, TTTTransition<String, String>, String>) learningOracle.getHypothesisModel();

        LogManager.logger.logPhase("This round of learning is over.");
        roundNum = (int) round.getCount();
    }

    private void findCounterExample() {
        LogManager.logger.logPhase("Searching for counter-example");

        // Set to currently in the conformance verification phase
        learningStage = EQUIVALENCE_STAGE;
        SimpleProfiler.start("Searching for counter-example");
        counterExample = equivalenceOracle.findCounterExample(hypothesis, alphabet);
        SimpleProfiler.stop("Searching for counter-example");
    }

    public void learn(String resultFile) throws IOException {
        boolean stop = false;
        while (!stop) {
            try {
                LogManager.logger.logEvent("-----------------------------------------------------------------------------------");
                LogManager.logger.logPhase("Start Learning");
                roundNum = 0;

                SimpleProfiler.start("Total time");
                boolean learning = true;

                do {
                    getHypothesis();
                    if (writeNum < roundNum) {
                        Tool.writeDotModel(hypothesis, alphabet, config.outputDir + "/" + resultFile + "_hypothesis_" + round.getCount() + ".dot");
                        writeNum = roundNum;
                    }

                    // Searching for counter-example
                    findCounterExample();

                    if (counterExample == null) {
                        learning = false;
                        Tool.writeDotModel(hypothesis, alphabet, config.outputDir + "/" + resultFile + "_final_model.dot");
                    } else {
                        // If there is a counterexample, proceed to the next round of member query
                        LogManager.logger.logCounterexample("Current counterexample: " + counterExample);

                        // Check counterexamples through voting mechanisms
                        if (!mediator.isUseCache() && !Tool.checkCounterexample(config, cache, network)){
                            LogManager.logger.logPhase("Restart for counterexample");
                            reLearn();
                            break;
                        }
                        // Counterexamples are added to the hypothesis by counterexample checking

                    }
                } while (learning);

                // The model learning phase is over and the result is output
                if (!learning) {
                    SimpleProfiler.stop("Total time");
                    LogManager.logger.logEvent("-------------------------------------------------------");
                    SimpleProfiler.logResults();
                    LogManager.logger.logEvent(round.getSummary());
                    LogManager.logger.logEvent(statisticMqSul.getStatisticalData().getSummary());
                    LogManager.logger.logEvent(statisticEqSul.getStatisticalData().getSummary());
                    LogManager.logger.logEvent("States in final hypothesis: " + hypothesis.size());

                    // Stop Learning
                    stop = true;
                    cache.writeCacheForFinish();
                }
            } catch (RestartException e) {
                if (Objects.equals(e.getMessage(), "Restart for hooking")) {
                    LogManager.logger.logEvent("Restart for hooking");
                    reLearn();
                } else if (Objects.equals(e.getMessage(), "Restart for state fuzzing")) {
                    if (config.fuzzDepth == 0) {
                        LogManager.logger.logEvent("Fuzzing depth is 0, stop");
                        return;
                    }
                    LogManager.logger.logEvent("Restart for state fuzzing");
                    reLearn();
                } else if (Objects.equals(e.getMessage(), "Restart for sending")) {
                    LogManager.logger.logEvent("Restart for sending");
                    reLearn();
                }
            } catch (IllegalArgumentException e) {
                // Dealing with nondeterministic problems
                Timestamp start = new Timestamp(System.currentTimeMillis());
                if (!checkConflict(start)) {
                    // Stop Learning
                    stop = true;
                    LogManager.logger.logEvent("The same nondeterministic query is generated too many times");
                    network.closeConnection();
                }
            } catch (IllegalMonitorStateException | IndexOutOfBoundsException e) {
                if (mediator.isNull())
                    // If the error is caused by an empty string, ignore it directly
                    stop = checkTimes();
                else
                    // If the fault is caused by the client initiating a restart
                    LogManager.logger.logEvent("Restart for RestartException");
                // The restart limit was not reached. Procedure
                if (!stop) {
                    // Determines the current number of input sequences when an error occurs
                    if (!mediator.isReset())
                        cache.reloadCache();
                    reLearn();
                }
            } catch (NoSuchElementException e) {
                LogManager.logger.logEvent("Restart for NoSuchElementException");
                reLearn();
            }

        }
    }

    public void stateFuzz() throws IOException {
        LogManager.logger.logEvent("stateFuzz");
        cache.reconfigure(config.checkCacheFile);
        mediator.turnStage(hypothesis);
        stage = STATE_FUZZ;
        start();
        learn("state_fuzzing");

        LogManager.logger.logEvent("The number of actions which need to be hooked:" + mediator.getDiscoverNum());
        LogManager.logger.logEvent("The number of actions which were hooked:" + mediator.getHookNum());
    }

    private boolean checkTimes() {
        if (lastConflictNum == cache.getIndex()) {
            restartNum++;
        } else
            restartNum = 0;
        return restartNum >= 3;
    }

    private boolean checkConflict(Timestamp start) throws IOException {
        BufferedWriter writer = new BufferedWriter(new FileWriter(config.statisticsFile, true));
        if(checkTimes()){
            writer.write("Check failure\n");
            writer.close();
            return false;
        }
        writer.write("Check conflict\n");
        List<String> symbol, finalResult;
        symbol = new ArrayList<>(cache.getSymbol());
        cache.reloadCache();
        mediator.clearMap();
        if (learningStage == LEARNING_STAGE){
            writer.write("          stage: learning\n");
            writer.write("          start time: " + new Timestamp(System.currentTimeMillis()));
            writer.newLine();
            LogManager.logger.logEvent("Check conflict query during learning");
            finalResult = Tool.processVotes(symbol, network, config.voteNum, config.useNoElement);
            cache.reloadCache(symbol, finalResult, start);
            mediator.addMap(symbol, finalResult);
            writer.write("          finish time: " + new Timestamp(System.currentTimeMillis()));
            writer.newLine();
        } else if (learningStage == EQUIVALENCE_STAGE) {
            writer.write("          stage: equivalence\n");
            LogManager.logger.logEvent("Find conflict query during equivalence");
        }
        writer.close();
        LogManager.logger.logEvent("Restart for conflict query");
        reLearn();
        return true;
    }
}
