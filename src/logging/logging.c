#include "../include/logging.h"

#define DEFAULT_LOG_DIR "./log"
#define DEFAULT_LOG_FILE (DEFAULT_LOG_DIR "/%02d-%02d-%04d_%02d-%02d.log")
#define DEFAULT_LOG_FILE_MAXSTRLEN 64

/** The minimum allowed length for the log writing buffer. */
#define LOG_MIN_BUFFER_SIZE 0x1000 // 4 KBs
/** The maximum allowed length for the log writing buffer. */
#define LOG_MAX_BUFFER_SIZE 0x400000 // 4 MBs
/** The amount of bytes to expand the log buffer by when expanding. */
#define LOG_BUFFER_SIZE_GRANULARITY 0x1000 // 4 KBs
/** The maximum length a single print into the log buffer SHOULD require. */
#define LOG_BUFFER_MAX_PRINT_LENGTH 0x200 // 512 bytes

#define LOG_FILE_PERMISSION_BITS 777
#define LOG_DIR_PERMISSION_BITS 777
#define LOG_FILE_OPEN_FLAGS (O_WRONLY | O_APPEND | O_CREAT | O_NONBLOCK)

static const char* levels[] = {"[DEBUG]", "[INFO]","[OUTPUT]","[WARNING]","[ERROR]"};

const char* loggerGetLevel(TLogLevel level){
    return levels[level];
}

#ifndef DISABLE_LOGGER

/** The buffer where logs are buffered. */
static char* buffer = NULL;
static size_t bufferStart = 0, bufferLength = 0, bufferCapacity = 0;

/** The file descriptor for writing logs to disk, or -1 if we're not doing that. */
static int logFileFd = -1;
static fd_selector selector = NULL;
static TLogLevel logLevel = MIN_LOG_LEVEL;

/** The stream for writing logs to, or NULL if we're not doing that. */
static FILE* logStream = NULL;

/**
 * @brief Attempts to make at least len bytes available in the log buffer.
 */
static inline void makeBufferSpace(size_t len) {
    // Make enough space in the buffer for the string
    if (bufferLength + bufferStart + len > bufferCapacity) {
        // If the buffer can be compacted to fit this string, do so. Otherwise,
        // we'll have to allocate more memory.
        if (bufferCapacity <= len) {
            memmove(buffer, buffer + bufferStart, bufferLength);
            bufferStart = 0;
        } else if (bufferCapacity < LOG_MAX_BUFFER_SIZE) {
            size_t newBufferCapacity = bufferLength + len;
            newBufferCapacity = (newBufferCapacity + LOG_BUFFER_SIZE_GRANULARITY - 1) / LOG_BUFFER_SIZE_GRANULARITY * LOG_BUFFER_SIZE_GRANULARITY;
            if (newBufferCapacity > LOG_MAX_BUFFER_SIZE)
                newBufferCapacity = LOG_MAX_BUFFER_SIZE;

            // The buffer isn't large enough, let's try to expand it, or at
            // least compact it to make as much space available as possible.
            void* newBuffer = malloc(newBufferCapacity);
            if (newBuffer == NULL) {
                memmove(buffer, buffer + bufferStart, bufferLength);
                bufferStart = 0;
            } else {
                memcpy(newBuffer, buffer + bufferStart, bufferLength);
                free(buffer);
                buffer = newBuffer;
                bufferCapacity = newBufferCapacity;
                bufferStart = 0;
            }
        }
    }
}

/**
 * @brief Attempts to flush as much of the logging buffer into the logging file as it can.
 * This is performed with nonblocking writes. If any bytes are left for writing, we tell the
 * selector to notify us when writing is available and retry once that happens.
 */
static inline void tryFlushBufferToFile(void) {

    ssize_t written = write(logFileFd, buffer + bufferStart, bufferLength);
    if (written > 0) {
        bufferLength -= written;
        bufferStart = (bufferLength == 0 ? 0 : (bufferStart + written));
    }


    selector_set_interest(selector, logFileFd, bufferLength > 0 ? OP_WRITE : OP_NOOP);
}

static void fdWriteHandler(selector_key_t* key) {
    (void) key;
    tryFlushBufferToFile();
}

static void fdCloseHandler(selector_key_t* key) {
    (void) key;
    

    if (bufferLength != 0) {
       
        int flags = fcntl(logFileFd, F_GETFD, 0);
        fcntl(logFileFd, F_SETFL, flags & (~O_NONBLOCK));
        ssize_t written = write(logFileFd, buffer, bufferLength);
        if (written > 0) {
            bufferLength -= written;
            bufferStart = (bufferLength == 0 ? 0 : (bufferStart + written));
        }
    }

    close(logFileFd);
    logFileFd = -1;
}

static fd_handler fdHandler = {
    .handle_read = NULL,
    .handle_write = fdWriteHandler,
    .handle_close = fdCloseHandler,
    .handle_block = NULL};

/**
 * @brief Attempts to open a file for logging. Returns the fd, or -1 if failed.
 */
static int tryOpenLogfile(const char* logFile, struct tm tm) {
    if (logFile == NULL)
        return -1;

    char logfilebuf[DEFAULT_LOG_FILE_MAXSTRLEN + 1];


    if (logFile[0] == '\0') {
        snprintf(logfilebuf, DEFAULT_LOG_FILE_MAXSTRLEN, DEFAULT_LOG_FILE, 
                 tm.tm_mday, tm.tm_mon + 1, tm.tm_year + 1900,
                 tm.tm_hour, tm.tm_min);
        logFile = logfilebuf;

    
        mkdir(DEFAULT_LOG_DIR, LOG_DIR_PERMISSION_BITS);
    }


    int fd = open(logFile, LOG_FILE_OPEN_FLAGS, LOG_FILE_PERMISSION_BITS);
    if (fd < 0) {
        fprintf(stderr, "LOG_WARNING: Failed to open logging file at %s. The server will still run, but with logging disabled.\n", logFile);
        return -1;
    }

    return fd;
}

int loggerInit(fd_selector selectorParam, const char* logFile, FILE* logStreamParam) {

    time_t timeNow = time(NULL);
    struct tm tm = *localtime(&timeNow);

    selector = selectorParam;
    logFileFd = selectorParam == NULL ? -1 : tryOpenLogfile(logFile, tm);
    logStream = logStreamParam;
    logLevel = MIN_LOG_LEVEL;

   
    if (logFileFd >= 0)
        selector_register(selector, logFileFd, &fdHandler, OP_NOOP, NULL);

   
    if (logFileFd >= 0 || logStream != NULL) {
        buffer = malloc(LOG_MIN_BUFFER_SIZE);
        bufferCapacity = LOG_MIN_BUFFER_SIZE;
        bufferLength = 0;
        bufferStart = 0;
        if (buffer == NULL) {
            close(logFileFd);
            logFileFd = -1;
            fprintf(stderr, "LOG_WARNING: Failed to malloc a buffer for logging. You don't have 4KBs?\n");
            return -1;
        }
    }

    return 0;
}

int loggerFinalize(void) {
   
    if (logFileFd >= 0) {
        selector_unregister_fd(selector, logFileFd); 
        selector = NULL;
    }


    if (buffer != NULL) {
        free(buffer);
        buffer = NULL;
        bufferCapacity = 0;
        bufferLength = 0;
        bufferStart = 0;
    }

    logStream = NULL;
    return 0;
}

void loggerSetLevel(TLogLevel level) {
    logLevel = level;
}

int loggerIsEnabledFor(TLogLevel level) {
    return level >= logLevel && (logFileFd > 0 || logStream != NULL);
}

void loggerPrePrint(void) {
    makeBufferSpace(LOG_BUFFER_MAX_PRINT_LENGTH);
}

void loggerGetBufstartAndMaxlength(char** bufstartVar, size_t* maxlenVar) {
    *maxlenVar = bufferCapacity - bufferLength - bufferStart;
    *bufstartVar = buffer + bufferStart + bufferLength;
}

int loggerPostPrint(int written, size_t maxlen) {
    if (written < 0) {
        fprintf(stderr, "Error: snprintf(): %s\n", strerror(errno));
        return -1;
    }

    if ((size_t)written >= maxlen) {
        fprintf(stderr, "Error: %lu bytes of logs possibly lost. Slow disk?\n", written - maxlen + 1);
        written = maxlen - 1;
    }

    if (logStream != NULL) {
        fprintf(logStream, "%s", buffer + bufferStart + bufferLength);
    }

    if (logFileFd >= 0) {
        bufferLength += written;
        tryFlushBufferToFile();
    }
    return 0;
}

#endif // #ifndef DISABLE_LOGGER
