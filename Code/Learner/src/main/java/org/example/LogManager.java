package org.example;

import de.learnlib.logging.Category;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.helpers.SubstituteLogger;

import java.util.Objects;

public class LogManager extends SubstituteLogger {
    public static LogManager logger;

    private LogManager(Logger delegate) {
        super(delegate.getName(), null, false);
        super.setDelegate(delegate);
    }

    public static LogManager getLogger(String name) {
        if (logger == null || !Objects.equals(logger.getName(), name)) {
            logger = new LogManager(LoggerFactory.getLogger(name));
        }
        return logger;
    }

    public static LogManager getLogger(Class<?> clazz) {
        return getLogger(clazz.getName());
    }

    public void logEvent(String desc) {
        this.info(Category.EVENT, desc);
    }

    public void logEvent(String desc, boolean isLog) {
        if (isLog)
            this.info(Category.EVENT, desc);
    }

    public void logConfig(String conf) {
        this.info(Category.CONFIG, conf);
    }

    public void logQuery(boolean isLog, String type, String symbol, String result) {
        if (isLog && !Objects.equals(type, "CACHE"))
            this.info(Category.QUERY, "[" + type + "] Step: " + symbol + " - Result: " + result);
    }

    public void logPhase(String phase) {
        if (Learner.getWriteNum() < Learner.getRoundNum())
            this.info(Category.PHASE, phase);
    }

    public void logCounterexample(String ce) {
        if (Learner.getWriteNum() < Learner.getRoundNum())
            this.info(Category.COUNTEREXAMPLE, ce);
    }

    public static void resetName(String newName) {
        logger = getLogger(newName);
    }
}