#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "regex.h"
#include <pthread.h>
#include <time.h>
#include <ctype.h>
#include <stdbool.h>
#include <errno.h>

#include "log_analyzer.h"
#include "config.h"

char* strptime(const char* s, const char* format, struct tm* tm) {
    if (strcmp(format, "%Y-%m-%d %H:%M:%S") == 0) {
        int year = 0, month = 0, day = 0, hour = 0, minute = 0, second = 0;
        if (sscanf(s, "%d-%d-%d %d:%d:%d", &year, &month, &day, &hour, &minute, &second) != 6) {
            return NULL;
        }
        
        tm->tm_year = year - 1900;
        tm->tm_mon = month - 1;
        tm->tm_mday = day;
        tm->tm_hour = hour;
        tm->tm_min = minute;
        tm->tm_sec = second;
        tm->tm_isdst = -1;
        
        return (char*)(s + strlen(s));
    }
    
    return NULL;
}

LogFormat** g_formats;
int* g_num_formats;

void add_format_callback(const char* name, const char* pattern) {
    add_log_format(g_formats, g_num_formats, name, pattern);
}

int main(int argc, char** argv) {
    char* filename = NULL;
    char* format_name = "combined";
    int top_ip = 10;
    int top_url = 10;
    int top_useragent = 10;
    char* ip_filter = NULL;
    char* url_filter = NULL;
    time_t start_time = 0;
    time_t end_time = 0;
    bool time_stats_enabled = false;
    char* config_file = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-f") == 0 && i + 1 < argc) {
            format_name = argv[++i];
        } else if (strcmp(argv[i], "-l") == 0 && i + 1 < argc) {
            filename = argv[++i];
        } else if (strcmp(argv[i], "-topip") == 0 && i + 1 < argc) {
            top_ip = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-topurl") == 0 && i + 1 < argc) {
            top_url = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-topua") == 0 && i + 1 < argc) {
            top_useragent = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-ip") == 0 && i + 1 < argc) {
            ip_filter = argv[++i];
        } else if (strcmp(argv[i], "-url") == 0 && i + 1 < argc) {
            url_filter = argv[++i];
        } else if (strcmp(argv[i], "-time") == 0 && i + 1 < argc) {
            if (strcmp(argv[i + 1], "stats") == 0) {
                time_stats_enabled = true;
                i++;
            }
        } else if (strcmp(argv[i], "-start") == 0 && i + 1 < argc) {
            struct tm tm_info = {0};
            strptime(argv[++i], "%Y-%m-%d %H:%M:%S", &tm_info);
            start_time = mktime(&tm_info);
        } else if (strcmp(argv[i], "-end") == 0 && i + 1 < argc) {
            struct tm tm_info = {0};
            strptime(argv[++i], "%Y-%m-%d %H:%M:%S", &tm_info);
            end_time = mktime(&tm_info);
        } else if (strcmp(argv[i], "-config") == 0 && i + 1 < argc) {
            config_file = argv[++i];
        } else if (strcmp(argv[i], "-h") == 0) {
            print_usage();
            exit(EXIT_SUCCESS);
        }
    }

    if (filename == NULL) {
        fprintf(stderr, "Error: Log file not specified\n");
        print_usage();
        return EXIT_FAILURE;
    }

    LogFormat* formats = NULL;
    int num_formats = 0;
    init_log_formats(&formats, &num_formats);

    g_formats = &formats;
    g_num_formats = &num_formats;

    if (config_file != NULL) {
        load_log_format_from_json(config_file, add_format_callback);
    }

    LogFormat* selected_format = NULL;
    for (int i = 0; i < num_formats; i++) {
        if (strcmp(formats[i].name, format_name) == 0) {
            selected_format = &formats[i];
            break;
        }
    }

    if (selected_format == NULL) {
        fprintf(stderr, "Error: Unknown log format '%s'\n", format_name);
        return EXIT_FAILURE;
    }

    FILE* file = fopen(filename, "r");
    if (file == NULL) {
        fprintf(stderr, "Error: Cannot open file '%s': %s\n", filename, strerror(errno));
        return EXIT_FAILURE;
    }

    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    AnalyzerStats stats;
    init_analyzer_stats(&stats);

    int num_threads = 4;

    long chunk_size = file_size / num_threads;
    
    pthread_t* threads = (pthread_t*)malloc(num_threads * sizeof(pthread_t));
    ThreadData* thread_data = (ThreadData*)malloc(num_threads * sizeof(ThreadData));

    for (int i = 0; i < num_threads; i++) {
        thread_data[i].file = file;
        thread_data[i].start_offset = i * chunk_size;
        thread_data[i].end_offset = (i == num_threads - 1) ? file_size : (i + 1) * chunk_size;
        thread_data[i].format = selected_format;
        thread_data[i].stats = &stats;
        thread_data[i].ip_filter = ip_filter;
        thread_data[i].url_filter = url_filter;
        thread_data[i].start_time_filter = start_time;
        thread_data[i].end_time_filter = end_time;

        if (pthread_create(&threads[i], NULL, process_log_chunk, &thread_data[i]) != 0) {
            fprintf(stderr, "Error: Failed to create thread %d\n", i);
            return EXIT_FAILURE;
        }
    }

    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }

    printf("\n===== Analysis Results =====\n\n");

    if (top_ip > 0) {
        print_top_n(stats.ip_stats.ips, stats.ip_stats.counts, stats.ip_stats.size, top_ip, "Top IP Addresses");
    }

    if (top_url > 0) {
        print_top_n(stats.url_stats.urls, stats.url_stats.counts, stats.url_stats.size, top_url, "Top URLs");
    }

    if (top_useragent > 0) {
        print_top_n(stats.useragent_stats.useragents, stats.useragent_stats.counts, stats.useragent_stats.size, top_useragent, "Top User Agents");
    }

    print_response_code_stats(stats.response_codes, "HTTP Response Codes");

    if (time_stats_enabled) {
        printf("\n----- Time-based Statistics -----\n");
        printf("Requests per hour:\n");
        for (int i = 0; i < 24; i++) {
            printf("%02d:00 - %02d:59: %d requests\n", i, i, stats.time_stats.counts_per_hour[i]);
        }
    }

    free(threads);
    free(thread_data);
    free_analyzer_stats(&stats);
    for (int i = 0; i < num_formats; i++) {
        regfree(&formats[i].regex);
        free(formats[i].name);
        free(formats[i].pattern);
    }
    free(formats);
    fclose(file);

    return EXIT_SUCCESS;
} 