#ifndef LOG_ANALYZER_H
#define LOG_ANALYZER_H

#include <stdbool.h>
#include <time.h>

#include "regex.h"

typedef struct {
    char* ip;
    char* datetime;
    char* method;
    char* url;
    int code;
    long size;
    char* referer;
    char* useragent;
} LogEntry;

typedef struct {
    char* name;
    char* pattern;
    regex_t regex;
} LogFormat;

typedef struct {
    regmatch_t* matches;
    int nmatch;
} RegexMatches;

typedef struct {
    struct {
        char** ips;
        int* counts;
        int size;
        int capacity;
    } ip_stats;

    struct {
        char** urls;
        int* counts;
        int size;
        int capacity;
    } url_stats;

    int response_codes[600];

    struct {
        char** useragents;
        int* counts;
        int size;
        int capacity;
    } useragent_stats;

    struct {
        time_t start_time;
        time_t end_time;
        int* counts_per_hour;
    } time_stats;

    pthread_mutex_t mutex;
} AnalyzerStats;

typedef struct {
    FILE* file;
    long start_offset;
    long end_offset;
    LogFormat* format;
    AnalyzerStats* stats;
    char* ip_filter;
    char* url_filter;
    time_t start_time_filter;
    time_t end_time_filter;
} ThreadData;

void init_log_formats(LogFormat** formats, int* num_formats);
void add_log_format(LogFormat** formats, int* num_formats, const char* name, const char* pattern);
void compile_regex(LogFormat* format);
RegexMatches* create_regex_matches(int nmatch);
void free_regex_matches(RegexMatches* matches);
bool parse_log_entry(char* line, LogFormat* format, LogEntry* entry, RegexMatches* matches);
void free_log_entry(LogEntry* entry);
void init_analyzer_stats(AnalyzerStats* stats);
void free_analyzer_stats(AnalyzerStats* stats);
void* process_log_chunk(void* arg);
void update_ip_stats(AnalyzerStats* stats, const char* ip);
void update_url_stats(AnalyzerStats* stats, const char* url);
void update_response_code_stats(AnalyzerStats* stats, int code);
void update_useragent_stats(AnalyzerStats* stats, const char* useragent);
void update_time_stats(AnalyzerStats* stats, const char* datetime);
void print_top_n(char** items, int* counts, int size, int n, const char* title);
void print_response_code_stats(int* codes, const char* title);
time_t parse_datetime(const char* datetime);
void print_usage();
void parse_command_line(int argc, char** argv, char** filename, char** format_name, 
                        int* top_ip, int* top_url, int* top_useragent, 
                        char** ip_filter, char** url_filter,
                        time_t* start_time, time_t* end_time, bool* time_stats);

#endif