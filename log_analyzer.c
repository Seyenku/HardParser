#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
#include <ctype.h>
#include <stdbool.h>
#include <errno.h>

#include "regex.h"
#include "log_analyzer.h"

void init_log_formats(LogFormat** formats, int* num_formats) {
    *num_formats = 2;
    *formats = (LogFormat*)malloc(*num_formats * sizeof(LogFormat));

    (*formats)[0].name = _strdup("common"); // делает копию строки и возвращает новый указатель.
    (*formats)[0].pattern = _strdup("^([\\d.]+) \\S+ \\S+ \\[([^\\]]+)\\] \"([A-Z]+) ([^ \"]+)[^\"]*\" (\\d+) (\\d+|-)$");
    compile_regex(&(*formats)[0]);

    (*formats)[1].name = _strdup("combined");
    (*formats)[1].pattern = _strdup("^([\\d.]+) \\S+ \\S+ \\[([^\\]]+)\\] \"([A-Z]+) ([^ \"]+)[^\"]*\" (\\d+) (\\d+|-) \"([^\"]*)\" \"([^\"]*)\"$");
    compile_regex(&(*formats)[1]);
}

void add_log_format(LogFormat** formats, int* num_formats, const char* name, const char* pattern) {
    for (int i = 0; i < *num_formats; i++) {
        if (strcmp((*formats)[i].name, name) == 0) {
            free((*formats)[i].pattern);
            (*formats)[i].pattern = _strdup(pattern);
            regfree(&(*formats)[i].regex);
            compile_regex(&(*formats)[i]);
            return;
        }
    }

    *formats = (LogFormat*)realloc(*formats, (*num_formats + 1) * sizeof(LogFormat));
    (*formats)[*num_formats].name = _strdup(name);
    (*formats)[*num_formats].pattern = _strdup(pattern);
    compile_regex(&(*formats)[*num_formats]);
    (*num_formats)++;
}

void compile_regex(LogFormat* format) {
    int ret = regcomp(&format->regex, format->pattern, REG_EXTENDED);
    if (ret != 0) {
        char error_buffer[100];
        regerror(ret, &format->regex, error_buffer, sizeof(error_buffer));
        fprintf(stderr, "Error compiling regex pattern '%s': %s\n", format->pattern, error_buffer);
        exit(EXIT_FAILURE);
    }
}

RegexMatches* create_regex_matches(int nmatch) {
    RegexMatches* matches = (RegexMatches*)malloc(sizeof(RegexMatches));
    matches->nmatch = nmatch;
    matches->matches = (regmatch_t*)malloc(nmatch * sizeof(regmatch_t));
    return matches;
}

void free_regex_matches(RegexMatches* matches) {
    free(matches->matches);
    free(matches);
}

bool parse_log_entry(char* line, LogFormat* format, LogEntry* entry, RegexMatches* matches) {
    int ret = regexec(&format->regex, line, matches->nmatch, matches->matches, 0);
    if (ret != 0) {
        return false;
    }

    int ip_idx = 1;
    int datetime_idx = 2;
    int method_idx = 3;
    int url_idx = 4;
    int code_idx = 5;
    int size_idx = 6;
    int referer_idx = 7;
    int useragent_idx = 8;

    regmatch_t* m = &matches->matches[ip_idx];
    int len = m->rm_eo - m->rm_so;
    entry->ip = (char*)malloc(len + 1);
    strncpy(entry->ip, line + m->rm_so, len);
    entry->ip[len] = '\0';

    m = &matches->matches[datetime_idx];
    len = m->rm_eo - m->rm_so;
    entry->datetime = (char*)malloc(len + 1);
    strncpy(entry->datetime, line + m->rm_so, len);
    entry->datetime[len] = '\0';

    m = &matches->matches[method_idx];
    len = m->rm_eo - m->rm_so;
    entry->method = (char*)malloc(len + 1);
    strncpy(entry->method, line + m->rm_so, len);
    entry->method[len] = '\0';

    m = &matches->matches[url_idx];
    len = m->rm_eo - m->rm_so;
    entry->url = (char*)malloc(len + 1);
    strncpy(entry->url, line + m->rm_so, len);
    entry->url[len] = '\0';

    m = &matches->matches[code_idx];
    len = m->rm_eo - m->rm_so;
    char* code_str = (char*)malloc(len + 1);
    strncpy(code_str, line + m->rm_so, len);
    code_str[len] = '\0';
    entry->code = atoi(code_str);
    free(code_str);

    m = &matches->matches[size_idx];
    len = m->rm_eo - m->rm_so;
    char* size_str = (char*)malloc(len + 1);
    strncpy(size_str, line + m->rm_so, len);
    size_str[len] = '\0';
    if (strcmp(size_str, "-") == 0) {
        entry->size = 0;
    } else {
        entry->size = atol(size_str);
    }
    free(size_str);
                         
    if (strcmp(format->name, "common") == 0) {
        entry->referer = _strdup("-");
        entry->useragent = _strdup("-");
    } else {
        m = &matches->matches[referer_idx];
        len = m->rm_eo - m->rm_so;
        entry->referer = (char*)malloc(len + 1);
        strncpy(entry->referer, line + m->rm_so, len);
        entry->referer[len] = '\0';

        m = &matches->matches[useragent_idx];
        len = m->rm_eo - m->rm_so;
        entry->useragent = (char*)malloc(len + 1);
        strncpy(entry->useragent, line + m->rm_so, len);
        entry->useragent[len] = '\0';
    }

    return true;
}

void free_log_entry(LogEntry* entry) {
    free(entry->ip);
    free(entry->datetime);
    free(entry->method);
    free(entry->url);
    free(entry->referer);
    free(entry->useragent);
}

void init_analyzer_stats(AnalyzerStats* stats) {
    stats->ip_stats.ips = NULL;
    stats->ip_stats.counts = NULL;
    stats->ip_stats.size = 0;
    stats->ip_stats.capacity = 0;

    stats->url_stats.urls = NULL;
    stats->url_stats.counts = NULL;
    stats->url_stats.size = 0;
    stats->url_stats.capacity = 0;

    memset(stats->response_codes, 0, sizeof(stats->response_codes));

    stats->useragent_stats.useragents = NULL;
    stats->useragent_stats.counts = NULL;
    stats->useragent_stats.size = 0;
    stats->useragent_stats.capacity = 0;

    stats->time_stats.start_time = 0;
    stats->time_stats.end_time = 0;
    stats->time_stats.counts_per_hour = (int*)calloc(24, sizeof(int));

    pthread_mutex_init(&stats->mutex, NULL);
}

void free_analyzer_stats(AnalyzerStats* stats) {
    for (int i = 0; i < stats->ip_stats.size; i++) {
        free(stats->ip_stats.ips[i]);
    }
    free(stats->ip_stats.ips);
    free(stats->ip_stats.counts);

    for (int i = 0; i < stats->url_stats.size; i++) {
        free(stats->url_stats.urls[i]);
    }
    free(stats->url_stats.urls);
    free(stats->url_stats.counts);

    for (int i = 0; i < stats->useragent_stats.size; i++) {
        free(stats->useragent_stats.useragents[i]);
    }
    free(stats->useragent_stats.useragents);
    free(stats->useragent_stats.counts);

    free(stats->time_stats.counts_per_hour);

    pthread_mutex_destroy(&stats->mutex);
}

void* process_log_chunk(void* arg) {
    ThreadData* data = (ThreadData*)arg;
    FILE* file = data->file;
    LogFormat* format = data->format;
    AnalyzerStats* stats = data->stats;

    int nmatch = 9;
    RegexMatches* matches = create_regex_matches(nmatch);

    fseek(file, data->start_offset, SEEK_SET);

    if (data->start_offset > 0) {
        char c;
        do {
            c = fgetc(file);
            if (c == '\n' || c == EOF) {
                break;
            }
        } while (1);
    }

    char line[4096];

    while (ftell(file) < data->end_offset && fgets(line, sizeof(line), file) != NULL) {
        int len = strlen(line);
        if (len > 0 && line[len - 1] == '\n') {
            line[len - 1] = '\0';
        }

        LogEntry entry;
        if (!parse_log_entry(line, format, &entry, matches)) {
            continue;
        }

        if (data->ip_filter != NULL && strcmp(data->ip_filter, entry.ip) != 0) {
            free_log_entry(&entry);
            continue;
        }

        if (data->url_filter != NULL && strcmp(data->url_filter, entry.url) != 0) {
            free_log_entry(&entry);
            continue;
        }

        time_t entry_time = parse_datetime(entry.datetime);
        if (data->start_time_filter > 0 && entry_time < data->start_time_filter) {
            free_log_entry(&entry);
            continue;
        }

        if (data->end_time_filter > 0 && entry_time > data->end_time_filter) {
            free_log_entry(&entry);
            continue;
        }

        pthread_mutex_lock(&stats->mutex);
        update_ip_stats(stats, entry.ip);
        update_url_stats(stats, entry.url);
        update_response_code_stats(stats, entry.code);
        update_useragent_stats(stats, entry.useragent);
        update_time_stats(stats, entry.datetime);
        pthread_mutex_unlock(&stats->mutex);

        free_log_entry(&entry);
    }

    free_regex_matches(matches);

    return NULL;
}

void update_ip_stats(AnalyzerStats* stats, const char* ip) {
    for (int i = 0; i < stats->ip_stats.size; i++) {
        if (strcmp(stats->ip_stats.ips[i], ip) == 0) {
            stats->ip_stats.counts[i]++;
            return;
        }
    }

    if (stats->ip_stats.size >= stats->ip_stats.capacity) {
        int new_capacity = stats->ip_stats.capacity == 0 ? 100 : stats->ip_stats.capacity * 2;
        stats->ip_stats.ips = (char**)realloc(stats->ip_stats.ips, new_capacity * sizeof(char*));
        stats->ip_stats.counts = (int*)realloc(stats->ip_stats.counts, new_capacity * sizeof(int));
        stats->ip_stats.capacity = new_capacity;
    }

    stats->ip_stats.ips[stats->ip_stats.size] = _strdup(ip);
    stats->ip_stats.counts[stats->ip_stats.size] = 1;
    stats->ip_stats.size++;
}

void update_url_stats(AnalyzerStats* stats, const char* url) {
    for (int i = 0; i < stats->url_stats.size; i++) {
        if (strcmp(stats->url_stats.urls[i], url) == 0) {
            stats->url_stats.counts[i]++;
            return;
        }
    }

    if (stats->url_stats.size >= stats->url_stats.capacity) {
        int new_capacity = stats->url_stats.capacity == 0 ? 100 : stats->url_stats.capacity * 2;
        stats->url_stats.urls = (char**)realloc(stats->url_stats.urls, new_capacity * sizeof(char*));
        stats->url_stats.counts = (int*)realloc(stats->url_stats.counts, new_capacity * sizeof(int));
        stats->url_stats.capacity = new_capacity;
    }

    stats->url_stats.urls[stats->url_stats.size] = _strdup(url);
    stats->url_stats.counts[stats->url_stats.size] = 1;
    stats->url_stats.size++;
}

void update_response_code_stats(AnalyzerStats* stats, int code) {
    if (code >= 0 && code < 600) {
        stats->response_codes[code]++;
    }
}

void update_useragent_stats(AnalyzerStats* stats, const char* useragent) {
    // Check if User-Agent already exists
    for (int i = 0; i < stats->useragent_stats.size; i++) {
        if (strcmp(stats->useragent_stats.useragents[i], useragent) == 0) {
            stats->useragent_stats.counts[i]++;
            return;
        }
    }

    if (stats->useragent_stats.size >= stats->useragent_stats.capacity) {
        int new_capacity = stats->useragent_stats.capacity == 0 ? 100 : stats->useragent_stats.capacity * 2;
        stats->useragent_stats.useragents = (char**)realloc(stats->useragent_stats.useragents, new_capacity * sizeof(char*));
        stats->useragent_stats.counts = (int*)realloc(stats->useragent_stats.counts, new_capacity * sizeof(int));
        stats->useragent_stats.capacity = new_capacity;
    }

    stats->useragent_stats.useragents[stats->useragent_stats.size] = _strdup(useragent);
    stats->useragent_stats.counts[stats->useragent_stats.size] = 1;
    stats->useragent_stats.size++;
}

void update_time_stats(AnalyzerStats* stats, const char* datetime) {
    time_t timestamp = parse_datetime(datetime);
    if (timestamp == 0) {
        return;
    }

    struct tm* tm_info = localtime(&timestamp);
    if (tm_info != NULL) {
        stats->time_stats.counts_per_hour[tm_info->tm_hour]++;
    }
}

void print_top_n(char** items, int* counts, int size, int n, const char* title) {
    printf("\n----- %s -----\n", title);

    int* indices = (int*)malloc(size * sizeof(int));
    for (int i = 0; i < size; i++) {
        indices[i] = i;
    }

    for (int i = 0; i < size - 1; i++) {
        for (int j = i + 1; j < size; j++) {
            if (counts[indices[i]] < counts[indices[j]]) {
                int temp = indices[i];
                indices[i] = indices[j];
                indices[j] = temp;
            }
        }
    }

    int count = n < size ? n : size;
    for (int i = 0; i < count; i++) {
        printf("%d. %s: %d\n", i + 1, items[indices[i]], counts[indices[i]]);
    }

    free(indices);
}

void print_response_code_stats(int* codes, const char* title) {
    printf("\n----- %s -----\n", title);

    int common_codes[] = {200, 201, 204, 206, 301, 302, 303, 304, 307, 400, 401, 403, 404, 405, 406, 410, 500, 501, 502, 503, 504};
    int num_common_codes = sizeof(common_codes) / sizeof(common_codes[0]);

    for (int i = 0; i < num_common_codes; i++) {
        int code = common_codes[i];
        if (codes[code] > 0) {
            printf("%d: %d\n", code, codes[code]);
        }
    }

    for (int code = 100; code < 600; code++) {
        if (codes[code] > 0) {
            bool is_common = false;
            for (int i = 0; i < num_common_codes; i++) {
                if (code == common_codes[i]) {
                    is_common = true;
                    break;
                }
            }

            if (!is_common) {
                printf("%d: %d\n", code, codes[code]);
            }
        }
    }
}

time_t parse_datetime(const char* datetime) {
    struct tm tm_info = {0};
    char month_str[4];
    int timezone_offset;

    sscanf(datetime, "%d/%3s/%d:%d:%d:%d %d", 
           &tm_info.tm_mday, month_str, &tm_info.tm_year, 
           &tm_info.tm_hour, &tm_info.tm_min, &tm_info.tm_sec, 
           &timezone_offset);

    const char* months[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
    for (int i = 0; i < 12; i++) {
        if (strncmp(month_str, months[i], 3) == 0) {
            tm_info.tm_mon = i;
            break;
        }
    }

    tm_info.tm_year -= 1900;

    return mktime(&tm_info);
}

void print_usage() {
    printf("Usage: log_analyzer [options]\n");
    printf("Options:\n");
    printf("  -f <format>            Specify log format (common, combined)\n");
    printf("  -l <file>              Specify log file to analyze\n");
    printf("  -config <file>         Specify configuration file for custom log format\n");
    printf("  -topip <n>             Show top N IP addresses\n");
    printf("  -topurl <n>            Show top N URLs\n");
    printf("  -topua <n>             Show top N User Agents\n");
    printf("  -ip <ip>               Filter by IP address\n");
    printf("  -url <url>             Filter by URL\n");
    printf("  -time stats            Enable time-based statistics\n");
    printf("  -start <datetime>      Start time filter (format: YYYY-MM-DD HH:MM:SS)\n");
    printf("  -end <datetime>        End time filter (format: YYYY-MM-DD HH:MM:SS)\n");
    printf("  -h                     Show this help message\n");
    printf("\nExamples:\n");
    printf("  ./log_analyzer -f combined -l access.log -topip 10 -topurl 5 -time stats -start \"2023-10-26 00:00:00\" -end \"2023-10-26 23:59:59\"\n");
    printf("  ./log_analyzer -config custom_format.json -l access.log -topip 10\n");
} 