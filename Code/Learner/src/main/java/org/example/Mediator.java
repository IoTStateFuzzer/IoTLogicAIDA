package org.example;

import de.learnlib.algorithm.ttt.base.TTTState;
import de.learnlib.algorithm.ttt.base.TTTTransition;
import de.learnlib.sul.SUL;
import net.automatalib.alphabet.GrowingMapAlphabet;
import net.automatalib.automaton.transducer.MealyMachine;

import java.io.IOException;
import java.sql.Timestamp;
import java.util.*;

import static org.example.AlphabetManager.*;
import static org.example.Learner.*;

public class Mediator implements SUL<String, String> {
    public static final int CACHE_STAGE = 0;
    public static final int HOOK_STAGE = 1;
    public static final int MIDDLE_STAGE = 2;

    public static final String CACHE_REPLY = "CACHE";
    public static final String MODEL_REPLY = "MODEL";
    public static final String RULE_REPLY = "RULE";
    public static final String GUI_REPLY = "GUI";
    public static final String HOOK_REPLY = "HOOK";
    public static final String HISTORY_REPLY = "HISTORY";

    private static GrowingMapAlphabet<String> alphabet;
    private final NetworkManager network;
    private final CacheManager cache;
    private boolean useCache;
    private final boolean useTimestamp;
    private final boolean useNoElement;
    private final boolean useKnowledge;
    private final boolean queryOut;
    private boolean isReset;
    private boolean isNoElement;
    private boolean isNull;
    private boolean hook;
    private int currentReset;
    private int currentLocation, hookLocation;
    private int fuzzStage;
    private TTTState<String, String> currentState;
    private MealyMachine<TTTState<String, String>, String, TTTTransition<String, String>, String> baseModel;
    Map<TTTState<String, String>, List<String>> stateNoElementMap = new HashMap<>();

    private final Map<String, String> noElementMap = new HashMap<>();
    private final Map<String, String> currentMap = new HashMap<>();
    private String currentString;
    private boolean needSend = false;
    private boolean sending = false;
    private final boolean useHistory;

    private int discoverNum;
    private int hookNum;

    private String symbol, result, replyType;
    private Timestamp start, end;

    private boolean fistStep = true;


    public Mediator(Configuration config, NetworkManager network, CacheManager cache) {
        alphabet = new GrowingMapAlphabet<>(config.aM.words);
        this.network = network;
        this.cache = cache;
        currentReset = 0;
        this.useCache = config.useCache;
        this.useTimestamp = config.useTimestamp;
        this.useNoElement = config.useNoElement;
        this.useKnowledge = config.useKnowledge;
        this.useHistory = config.useHistory;
        this.queryOut = config.queryOut;
        discoverNum = hookNum = 0;
    }

    public GrowingMapAlphabet<String> getAlphabet() {
        return alphabet;
    }

    public boolean isUseCache() {
        return useCache;
    }

    public boolean isReset() {
        return isReset;
    }

    public boolean isNull() {
        return isNull;
    }

    public int getDiscoverNum() {
        return discoverNum;
    }

    public int getHookNum() {
        return hookNum;
    }

    public void clearMap() {
        currentMap.clear();
    }

    public void addMap(List<String> symbols, List<String> results) {
        currentString = "";
        for (int i = 1; i < symbols.size(); i++) {
            currentString += symbols.get(i);
            if (!noElementMap.containsKey(currentString)) {
                currentMap.put(currentString, results.get(i));
            }
        }
    }

    private void setStateNoElementMap() {
        var hypothesisSize = baseModel.size();
        if (hypothesisSize <= 0)
            LogManager.logger.logEvent("The hypothesis is empty！");
        LogManager.logger.logEvent("hypothesis.size: " + hypothesisSize);
        LogManager.logger.logEvent("hypothesis.getState: " + baseModel.getStates());

        Queue<TTTState<String, String>> stateQueue = new LinkedList<>();
        stateQueue.offer(baseModel.getInitialState());

        Set<TTTState<String, String>> stateSet = new HashSet<>();

        while (!stateQueue.isEmpty()) {
            TTTState<String, String> stateSource = stateQueue.poll(), stateDestination;
            List<String> NoElementList = new ArrayList<>();
            stateSet.add(stateSource);
            String output;
            for (String input : alphabet) {
                stateDestination = baseModel.getSuccessor(stateSource, input);
                if (!stateSet.contains(stateDestination))
                    stateQueue.offer(stateDestination);
                output = baseModel.getOutput(stateSource, input);
                if (Objects.equals(output, RESTRICTED_SYMBOL))
                    NoElementList.add(input);
            }
            stateNoElementMap.put(stateSource, NoElementList);
        }
        LogManager.logger.logEvent("stateNoElementMap: " + stateNoElementMap);
    }

    public void turnStage(MealyMachine<TTTState<String, String>, String, TTTTransition<String, String>, String> hypothesis) {
        this.baseModel = hypothesis;
        setStateNoElementMap();
        fuzzStage = CACHE_STAGE;
        currentReset = 0;
        hook = false;
        noElementMap.clear();
    }

    public void restartMediator() {
//        LogManager.logger.logEvent("Restart the Mediator", queryOut);
        currentReset = 0;
        useCache = true;
    }

    private boolean needHook(TTTState<String, String> state, String input) {
//        LogManager.logger.logEvent("CHECK HOOKING", queryOut);
        return stateNoElementMap.get(state).contains(input);
    }

    private void checkResult(String result, boolean isCache) {
        if (isCache) {
            if (Objects.equals(result, "Wrong_null")) {
                isNull = true;
                LogManager.logger.warn("Cache null");
                throw new RestartException(result);
            }
        } else {
            if (result.isEmpty()) {
                isNull = true;
                LogManager.logger.warn("Receive null");
                throw new RestartException(result);
            }
            if (Objects.equals(result, RESTART_LEARNING)) {
                LogManager.logger.warn(result);
                throw new RestartException(result);
            }
            if (result.equals(RESTRICTED_SYMBOL))
                isNoElement = true;
        }
    }

    private void sendQuery(String symbol) {
        try {
            start = new Timestamp(System.currentTimeMillis());
            result = network.sendQuery(symbol);
            end = new Timestamp(System.currentTimeMillis());
            checkResult(result, false);
        } catch (IOException e) {
            if (Objects.equals(symbol, RESET_SYMBOL))
                LogManager.logger.error("Reset fail");
            else
                LogManager.logger.error("Step fail: " + symbol);
        }
    }

    private void useCacheReply() {
        // Get result from cache
        result = cache.get(symbol);
        checkResult(result, true);
        replyType = CACHE_REPLY;
    }

    private void useRuleReply() {
        start = end = new Timestamp(System.currentTimeMillis());
        result = RESTRICTED_SYMBOL;
        replyType = RULE_REPLY;
    }

    private void useGUIReply() {
        sendQuery(symbol);
        replyType = GUI_REPLY;
    }

    private void useHookReply() {
        LogManager.logger.logEvent("Test for HOOKING", queryOut);
        symbol += "|hook";
        hook = true;
        sendQuery(symbol);
        replyType = HOOK_REPLY;
    }

    private void useModelReply() {
        result = baseModel.getOutput(currentState, symbol);
        currentState = baseModel.getSuccessor(currentState, symbol);
        start = end = new Timestamp(System.currentTimeMillis());
        checkResult(result, false);
        replyType = MODEL_REPLY;
    }

    private void useHistoryReply() {
        result = noElementMap.get(currentString);
        if (result.equals(RESTRICTED_SYMBOL)) {
            isNoElement = true;
        }
        start = end = new Timestamp(System.currentTimeMillis());
        checkResult(result, false);
        replyType = HISTORY_REPLY;
    }

    private void writeCache() {
        if (isReset) {
            if (useTimestamp) {
                cache.writeCacheInReset(start, end);
            } else
                cache.writeCacheWithoutTime();
        } else {
            if (useTimestamp) {
                cache.add(symbol, result, start, end);
            } else
                cache.add(symbol, result);
        }
    }

    private void stepForStateFuzzing() {
        currentLocation++;
        if (hook) {
            if (!useKnowledge || currentLocation >= hookLocation)
                useHookReply();
            else
                useGUIReply();
        }
        else {
            if (useKnowledge) {
                if (needHook(currentState, symbol)) {
                    discoverNum++;
                    if (symbol.startsWith("user2")) {
                        LogManager.logger.logEvent("------------------------[NEED HOOKING]------------------------");
                        hookNum++;
                        hookLocation = currentLocation;
                        fuzzStage = MIDDLE_STAGE;
                        cache.reloadCache();
                        hook = true;
                        throw new RestartException("Restart for hooking");
                    }
                }
                useModelReply();
            } else {
                if (needHook(currentState, symbol)) {
                    useHookReply();
                } else
                    useGUIReply();
            }
        }
    }

    // Rewrite the SUL interface function to push the system down
    @Override
    public String step(String symbol) {
        this.symbol = symbol;
        currentString += this.symbol;
//        LogManager.logger.logEvent("[STEP] " + this.symbol, queryOut);

        if (useCache) {
            useCacheReply();
            // Use cache and add history
            if (useHistory) {
                if (!noElementMap.containsKey(currentString))
                    noElementMap.put(currentString, result);
            }
        }
        else {
            LogManager.logger.logEvent("[STEP] " + this.symbol, queryOut);
            // Use rule to respond quickly
            if (useNoElement && isNoElement)
                useRuleReply();
            else {
                isReset = false;
                if (!useHistory || needSend) {
                    if (getStage() == BASE_MODEL)
                        useGUIReply();
                    else
                        stepForStateFuzzing();
                    // store temp maps
                    currentMap.put(currentString, result);
                } else {
                    if (noElementMap.containsKey(currentString)) {
                        LogManager.logger.logEvent("---------------------[CHECK HISTORY]→[USE HISTORY]----------------------", queryOut);
                        useHistoryReply();
                    } else {
                        LogManager.logger.logEvent("-------------------[CHECK HISTORY]→[NEED INTERACTION]-------------------");
                        needSend = true;
                        cache.reloadCache();
                        throw new RestartException("Restart for sending");
                    }
                }
            }
            writeCache();
        }
        LogManager.logger.logQuery(queryOut, replyType, this.symbol, result);
        return result;
    }

    private void preForStateFuzzing() {
        currentLocation = 0;
        currentState = baseModel.getInitialState();
        if (!useKnowledge)
            sendQuery(RESET_SYMBOL);
        else {
            if (fuzzStage == MIDDLE_STAGE) {
                LogManager.logger.logEvent( RESET_SYMBOL + " for HOOKING");
                fuzzStage = HOOK_STAGE;
                sendQuery(RESET_SYMBOL);
            } else {
                LogManager.logger.logEvent(RESET_SYMBOL + " for MODEL_TEST", queryOut);
                fuzzStage = CACHE_STAGE;
                hook = false;
                start = end = new Timestamp(System.currentTimeMillis());
            }
        }
    }

    // Rewrite the SUL interface function to initialize the target system
    @Override
    public void pre() {
        // Process conflict and history
        noElementMap.putAll(currentMap);
        currentString = "";

        if (fistStep && getStage() != BASE_MODEL) {
            fistStep = false;
            throw new RestartException("Restart for state fuzzing");
        }

        isReset = true;
        if (!useCache || currentReset >= cache.getResetNum()) {
            useCache = false;
            isNoElement = false;
            if (!useHistory || needSend) {
                LogManager.logger.logEvent("---------------------------------[" + RESET_SYMBOL + "]--------------------------------", queryOut);
                sending = true;
                if (getStage() == BASE_MODEL) {
                    sendQuery(RESET_SYMBOL);
                } else {
                    preForStateFuzzing();
                }
            } else {
                LogManager.logger.logEvent("--------------------------[" + RESET_SYMBOL + " WITH HISTORY]--------------------------", queryOut);
                start = end = new Timestamp(System.currentTimeMillis());
            }
            writeCache();
        }
        currentReset++;
        currentMap.clear();
    }

    @Override
    public void post() {
        if (useHistory && needSend && sending) {
            needSend = false;
            sending = false;
        }
    }
}
