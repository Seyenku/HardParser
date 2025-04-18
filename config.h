#ifndef CONFIG_H
#define CONFIG_H

void load_log_format_from_json(const char* filename, void (*add_format_callback)(const char*, const char*));

#endif