#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>
#include "regex.h"

typedef enum {
    JSON_NULL,
    JSON_BOOLEAN,
    JSON_NUMBER,
    JSON_STRING,
    JSON_ARRAY,
    JSON_OBJECT
} JsonType;

typedef struct JsonNode JsonNode;

typedef struct {
    char* key;
    JsonNode* value;
} JsonKeyValue;

struct JsonNode {
    JsonType type;
    union {
        bool boolean;
        double number;
        char* string;
        struct {
            JsonNode** items;
            int size;
            int capacity;
        } array;
        struct {
            JsonKeyValue* pairs;
            int size;
            int capacity;
        } object;
    } value;
};

JsonNode* parse_json(const char** json);
void free_json_node(JsonNode* node);
char* get_json_string(JsonNode* node, const char* key);
JsonNode* get_json_object(JsonNode* node, const char* key);

char* read_file_contents(const char* filename) {
    FILE* file = fopen(filename, "r");
    if (file == NULL) {
        return NULL;
    }

    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    char* buffer = (char*)malloc(file_size + 1);
    if (buffer == NULL) {
        fclose(file);
        return NULL;
    }

    size_t bytes_read = fread(buffer, 1, file_size, file);
    buffer[bytes_read] = '\0';

    fclose(file);
    return buffer;
}

JsonNode* parse_json_string(const char** json) {
    (*json)++;
    
    const char* start = *json;
    while (**json && **json != '"') {
        if (**json == '\\') {
            (*json)++;
        }
        (*json)++;
    }
    
    if (**json != '"') {
        return NULL;
    }
    
    int length = *json - start;
    char* str = (char*)malloc(length + 1);
    strncpy(str, start, length);
    str[length] = '\0';
    
    (*json)++;
    
    JsonNode* node = (JsonNode*)malloc(sizeof(JsonNode));
    node->type = JSON_STRING;
    node->value.string = str;
    
    return node;
}

JsonNode* parse_json_number(const char** json) {
    const char* start = *json;
    while (isdigit(**json) || **json == '.' || **json == '-' || **json == '+' || **json == 'e' || **json == 'E') {
        (*json)++;
    }
    
    int length = *json - start;
    char* str = (char*)malloc(length + 1);
    strncpy(str, start, length);
    str[length] = '\0';
    
    double number = atof(str);
    free(str);
    
    JsonNode* node = (JsonNode*)malloc(sizeof(JsonNode));
    node->type = JSON_NUMBER;
    node->value.number = number;
    
    return node;
}

JsonNode* parse_json_literal(const char** json) {
    if (strncmp(*json, "true", 4) == 0) {
        *json += 4;
        JsonNode* node = (JsonNode*)malloc(sizeof(JsonNode));
        node->type = JSON_BOOLEAN;
        node->value.boolean = true;
        return node;
    } else if (strncmp(*json, "false", 5) == 0) {
        *json += 5;
        JsonNode* node = (JsonNode*)malloc(sizeof(JsonNode));
        node->type = JSON_BOOLEAN;
        node->value.boolean = false;
        return node;
    } else if (strncmp(*json, "null", 4) == 0) {
        *json += 4;
        JsonNode* node = (JsonNode*)malloc(sizeof(JsonNode));
        node->type = JSON_NULL;
        return node;
    }
    
    return NULL;
}

JsonNode* parse_json_array(const char** json) {
    (*json)++;
    
    JsonNode* node = (JsonNode*)malloc(sizeof(JsonNode));
    node->type = JSON_ARRAY;
    node->value.array.items = NULL;
    node->value.array.size = 0;
    node->value.array.capacity = 0;
    
    while (isspace(**json)) {
        (*json)++;
    }
    
    if (**json == ']') {
        (*json)++;
        return node;
    }
    
    while (1) {
        JsonNode* value = parse_json(json);
        if (value == NULL) {
            return NULL;
        }
        
        if (node->value.array.size >= node->value.array.capacity) {
            int new_capacity = node->value.array.capacity == 0 ? 8 : node->value.array.capacity * 2;
            node->value.array.items = (JsonNode**)realloc(node->value.array.items, new_capacity * sizeof(JsonNode*));
            node->value.array.capacity = new_capacity;
        }
        
        node->value.array.items[node->value.array.size++] = value;
        
        while (isspace(**json)) {
            (*json)++;
        }
        
        if (**json == ']') {
            (*json)++;
            break;
        }
        
        if (**json != ',') {
            return NULL;
        }
        
        (*json)++;
        
        while (isspace(**json)) {
            (*json)++;
        }
    }
    
    return node;
}

JsonNode* parse_json_object(const char** json) {
    (*json)++;
    
    JsonNode* node = (JsonNode*)malloc(sizeof(JsonNode));
    node->type = JSON_OBJECT;
    node->value.object.pairs = NULL;
    node->value.object.size = 0;
    node->value.object.capacity = 0;
    
    while (isspace(**json)) {
        (*json)++;
    }
    
    if (**json == '}') {
        (*json)++;
        return node;
    }
    
    while (1) {
        if (**json != '"') {
            return NULL;
        }
        
        JsonNode* key_node = parse_json_string(json);
        if (key_node == NULL) {
            return NULL;
        }
        
        char* key = key_node->value.string;
        
        while (isspace(**json)) {
            (*json)++;
        }
        
        if (**json != ':') {
            free(key);
            return NULL;
        }
        
        (*json)++;
        
        while (isspace(**json)) {
            (*json)++;
        }
        
        JsonNode* value = parse_json(json);
        if (value == NULL) {
            free(key);
            return NULL;
        }
        
        if (node->value.object.size >= node->value.object.capacity) {
            int new_capacity = node->value.object.capacity == 0 ? 8 : node->value.object.capacity * 2;
            node->value.object.pairs = (JsonKeyValue*)realloc(node->value.object.pairs, new_capacity * sizeof(JsonKeyValue));
            node->value.object.capacity = new_capacity;
        }
        
        node->value.object.pairs[node->value.object.size].key = key;
        node->value.object.pairs[node->value.object.size].value = value;
        node->value.object.size++;
        
        while (isspace(**json)) {
            (*json)++;
        }
        
        if (**json == '}') {
            (*json)++;
            break;
        }
        
        if (**json != ',') {
            return NULL;
        }
        
        (*json)++;
        
        while (isspace(**json)) {
            (*json)++;
        }
    }
    
    return node;
}

JsonNode* parse_json(const char** json) {
    while (isspace(**json)) {
        (*json)++;
    }
    
    if (**json == '"') {
        return parse_json_string(json);
    } else if (**json == '{') {
        return parse_json_object(json);
    } else if (**json == '[') {
        return parse_json_array(json);
    } else if (isdigit(**json) || **json == '-') {
        return parse_json_number(json);
    } else {
        return parse_json_literal(json);
    }
}

void free_json_node(JsonNode* node) {
    if (node == NULL) {
        return;
    }
    
    switch (node->type) {
        case JSON_STRING:
            free(node->value.string);
            break;
        case JSON_ARRAY:
            for (int i = 0; i < node->value.array.size; i++) {
                free_json_node(node->value.array.items[i]);
            }
            free(node->value.array.items);
            break;
        case JSON_OBJECT:
            for (int i = 0; i < node->value.object.size; i++) {
                free(node->value.object.pairs[i].key);
                free_json_node(node->value.object.pairs[i].value);
            }
            free(node->value.object.pairs);
            break;
        default:
            break;
    }
    
    free(node);
}

char* get_json_string(JsonNode* node, const char* key) {
    if (node == NULL || node->type != JSON_OBJECT) {
        return NULL;
    }
    
    for (int i = 0; i < node->value.object.size; i++) {
        if (strcmp(node->value.object.pairs[i].key, key) == 0) {
            JsonNode* value = node->value.object.pairs[i].value;
            if (value->type == JSON_STRING) {
                return value->value.string;
            }
            return NULL;
        }
    }
    
    return NULL;
}

JsonNode* get_json_object(JsonNode* node, const char* key) {
    if (node == NULL || node->type != JSON_OBJECT) {
        return NULL;
    }
    
    for (int i = 0; i < node->value.object.size; i++) {
        if (strcmp(node->value.object.pairs[i].key, key) == 0) {
            JsonNode* value = node->value.object.pairs[i].value;
            if (value->type == JSON_OBJECT) {
                return value;
            }
            return NULL;
        }
    }
    
    return NULL;
}

void load_log_format_from_json(const char* filename, void (*add_format_callback)(const char*, const char*)) {
    char* json_str = read_file_contents(filename);
    if (json_str == NULL) {
        fprintf(stderr, "Error: Cannot read config file '%s'\n", filename);
        return;
    }
    
    JsonNode* root = parse_json((char**)&json_str);
    if (root == NULL) {
        fprintf(stderr, "Error: Invalid JSON in config file '%s'\n", filename);
        free(json_str);
        return;
    }
    
    char* format_name = get_json_string(root, "log_format");
    char* regex_pattern = get_json_string(root, "regex");
    
    if (format_name != NULL && regex_pattern != NULL) {
        regex_t regex;
        int ret = regcomp(&regex, regex_pattern, REG_EXTENDED);
        if (ret != 0) {
            char error_buffer[100];
            regerror(ret, &regex, error_buffer, sizeof(error_buffer));
            fprintf(stderr, "Error: Invalid regex pattern in config file '%s': %s\n", filename, error_buffer);
        } else {
            regfree(&regex);
            add_format_callback(format_name, regex_pattern);
            printf("Added custom log format '%s' from file '%s'\n", format_name, filename);
        }
    } else {
        fprintf(stderr, "Error: Missing required fields in config file '%s'\n", filename);
    }
    
    free_json_node(root);
    free(json_str);
} 