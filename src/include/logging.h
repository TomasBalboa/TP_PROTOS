#ifndef __LOGGING_H__
#define __LOGGING_H__

// #define DISABLE_LOGGER

#include "selector.h"
#include <stdio.h>
#include <stddef.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <errno.h>

typedef enum {
    LOG_DEBUG = 0,
    LOG_INFO,
    LOG_OUTPUT,
    LOG_WARNING,
    LOG_ERROR
} TLogLevel;

#define MIN_LOG_LEVEL LOG_DEBUG
#define MAX_LOG_LEVEL LOG_ERROR

const char* loggerGetLevel(TLogLevel);

#ifdef DISABLE_LOGGER

#define loggerInit(selector, logFile, logStream)
#define loggerFinalize()
#define loggerSetLevel(level)
#define loggerIsEnabledFor(level) 0
#define logf(level, format, ...)
#define log(level, s)
#define logClientAuthenticated(clientId, username, successful)

#else

int loggerInit(fd_selector selectorParam, const char* logFile, FILE* logStreamParam);

int loggerFinalize(void);

void loggerSetLevel(TLogLevel level);

int loggerIsEnabledFor(TLogLevel level);

void loggerPrePrint(void);

void loggerGetBufstartAndMaxlength(char** bufstartVar, size_t* maxlenVar);

int loggerPostPrint(int written, size_t maxlen);

#define logf(level, fmt, ...)                                                                                          \
    if (loggerIsEnabledFor(level)) {                                                                                   \
        loggerPrePrint();                                                                                              \
        time_t loginternal_time = time(NULL);                                                                          \
        struct tm loginternal_tm = *localtime(&loginternal_time);                                                      \
        size_t loginternal_maxlen;                                                                                     \
        char* loginternal_bufstart;                                                                                    \
        loggerGetBufstartAndMaxlength(&loginternal_bufstart, &loginternal_maxlen);                                     \
        int loginternal_written = snprintf(loginternal_bufstart, loginternal_maxlen,                                   \
                                           "%04d-%02d-%02dT%02d:%02d:%02d%s\t" fmt "\n",                               \
                                           loginternal_tm.tm_year + 1900, loginternal_tm.tm_mon + 1, loginternal_tm.tm_mday, \
                                           loginternal_tm.tm_hour, loginternal_tm.tm_min, loginternal_tm.tm_sec,     \
                                           level == LOG_OUTPUT ? "" : loggerGetLevel(level), __VA_ARGS__);                \
        loggerPostPrint(loginternal_written, loginternal_maxlen);                                                      \
    }

#define log(level, s) logf(level, "%s", s)

#endif

#endif
