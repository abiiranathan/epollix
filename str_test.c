#include "str.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

void test_str_new() {
  Str* str = str_new("Hello");
  assert(str);
  printf("Str: %s\n", str_data(str));
  printf("Length: %zu\n", str_length(str));
  str_free(str);
}

void test_str_compare() {
  Str* str1   = str_new("Hello");
  int result  = str_compare(str1, "World");
  int result2 = str_compare(str1, "Hello");

  printf("Comparison result: %d\n", result);
  printf("Comparison result 2: %d\n", result2);
  assert(result < 0);
  assert(result2 == 0);
  str_free(str1);
}

void test_str_copy() {
  Str *str, *copy;
  str  = str_new("Hello");
  copy = str_copy(str);

  printf("Copied string: %s\n", str_data(copy));
  assert(strcmp(str_data(copy), "Hello") == 0);

  str_free(str);
  str_free(copy);
}

void test_str_concat() {
  char dest[13];
  str_concat(dest, sizeof(dest), "Hello", " World!");
  assert(strcmp(dest, "Hello World!") == 0);
}

void test_str_length() {
  Str* str      = str_new("Hello");
  size_t length = str_length(str);
  assert(length == 5);
  str_free(str);
}

void test_str_at() {
  Str* str       = str_new("Hello");
  const char* ch = str_at(str, 2);
  assert(ch != NULL);

  printf("Character at index 2: %c\n", *ch);
  assert((char)*ch == 'l');
  str_free(str);
}

void test_str_contains() {
  Str* str = str_new("Hello, World!");

  bool contains = str_contains(str, "World");
  printf("Contains 'World': %s\n", contains ? "true" : "false");
  assert(contains);
  str_free(str);
}

void test_str_is_empty() {
  Str* str1 = str_new("");
  Str* str2 = str_new("Hello");

  bool empty1 = str_is_empty(str1);
  bool empty2 = str_is_empty(str2);

  printf("Empty string 1: %s\n", empty1 ? "true" : "false");
  printf("Empty string 2: %s\n", empty2 ? "true" : "false");

  assert(empty1);
  assert(!empty2);

  str_free(str1);
  str_free(str2);
}

void test_str_find() {
  Str* str  = str_new("Hello, World!");
  int index = str_find(str, "World");
  printf("Substring 'World' found at index: %d\n", index);
  assert(index == 7);
  str_free(str);
}

void test_str_replace() {
  char dest[16];
  str_replace(dest, sizeof(dest), "Hello World!", "World", "John");
  assert(strcmp(dest, "Hello John!") == 0);
}

void test_str_to_upper() {
  Str* str = str_new("hello");

  str_to_upper(str);
  printf("Uppercase string: %s\n", str_data(str));
  assert(strcmp(str_data(str), "HELLO") == 0);

  str_free(str);
}

void test_str_to_lower() {
  Str* str = str_new("HELLO");

  str_to_lower(str);
  printf("Lowercase string: %s\n", str_data(str));
  assert(strcmp(str_data(str), "hello") == 0);

  str_free(str);
}

void test_str_split() {
  Str* str = str_new("Hello,World,OpenAI");

  const char* delimiter = ",";
  size_t num_substrings = 0;

  char** substrings = str_split(str, delimiter, &num_substrings);
  printf("Number of substrings: %ld\n", num_substrings);

  for (int i = 0; i < num_substrings; i++) {
    printf("Split Substring %d -> : %s\n", i, substrings[i]);
  }

  // Free substrings
  str_free_substrings(substrings, num_substrings);
  str_free(str);
}

void test_str_split_max() {
  Str* str              = str_new("This is a test string to split into parts");
  const char* delimiter = " ";
  size_t max_split      = 5;

  size_t num_substrings = 0;
  char** substrings     = str_split_max(str, delimiter, &num_substrings, max_split);
  printf("Max substrings: %ld\n", num_substrings);
  for (int i = 0; i < num_substrings; i++) {
    printf("Split Substring %d -> : %s\n", i, substrings[i]);
  }

  str_free_substrings(substrings, num_substrings);
  assert(num_substrings == max_split);
}

void test_str_match() {
  Str* str = str_new("Hello, World!");

  bool matches = str_match(str, "Hello.*");
  printf("Matches regex: %s\n", matches ? "true" : "false");
  assert(matches);
  str_free(str);
}

void test_str_replace_all() {
  char dest[16];
  str_replace_all(dest, 16, "Hello, World!", "o", "x");

  printf("Replaced string: %s\n", dest);
  assert(strcmp(dest, "Hellx, Wxrld!") == 0);
}

void test_str_to_camel_case() {
  Str* str = str_new("hello world my_Dear_friends");

  str_to_camel_case(str);
  printf("Camel case string: %s\n", str_data(str));
  assert(strcmp(str_data(str), "HelloWorldMyDearFriends") == 0);

  str_free(str);
}

void test_str_to_title_case() {
  Str* str = str_new("hello world");
  assert(str);
  str_to_title_case(str);
  printf("Title case string: %s\n", str_data(str));
  assert(strcmp(str_data(str), "Hello World") == 0);

  str_free(str);
}

void test_str_to_snake_case() {
  Str* str = str_new("Hello World MyDearFriends");
  assert(str);
  str_to_snake_case(str);
  printf("Snake case string: %s\n", str_data(str));
  assert(strcmp(str_data(str), "hello_world_my_dear_friends") == 0);

  str_free(str);
}

void test_str_insert() {
  char dest[100];
  str_insert(dest, 100, "The C Language is efficiently dangerous", "very ", 30);
  assert(strcmp("The C Language is efficiently very dangerous", dest) == 0);
}

void test_str_remove() {
  Str* str = str_new("Hello, World!");
  assert(str);
  size_t index = 5;
  size_t count = 7;

  str_remove(str, index, count);
  printf("Removed string: %s\n", str_data(str));
  assert(strcmp(str_data(str), "Hello!") == 0);
  assert(str_length(str) == 6);

  str_free(str);
}

void test_str_join() {
  const char* substrings[3] = {"Hello", "World", "OpenAI"};
  int count                 = 3;
  char delimiter            = '-';

  char buf[20];
  str_join(substrings, count, delimiter, buf, sizeof(buf));

  printf("Joined string: %s\n", buf);
  assert(strcmp(buf, "Hello-World-OpenAI") == 0);

  // if buffer is small, nothing happens
  char buf2[10];
  str_join(substrings, count, delimiter, buf2, sizeof(buf2));
  assert(sizeof(buf2) == 10);

  // Test with empty delimiter
  const char* chars[3] = {"A", "B", "C"};
  int count2           = 3;
  char buf3[4];
  str_join(chars, count2, '\0', buf3, sizeof(buf3));
  assert(strcmp(buf3, "ABC") == 0);
}

void test_str_substring() {
  Str* str = str_new("Hello, World!");

  size_t start = 7;
  size_t end   = 12;

  char substr1[6];
  char substr2[4];

  str_substring(str, start, end, substr1, sizeof(substr1));
  str_substring(str, start, end, substr2, sizeof(substr2));

  printf("Substring 1: %s\n", substr1);
  printf("Substring 2: %s\n", substr2);

  // make sure str is not modified
  assert(strcmp(str_data(str), "Hello, World!") == 0);

  assert(strcmp(substr1, "World") == 0);
  // test proper truncation if small buffer
  assert(strcmp(substr2, "Wor") == 0);
  str_free(str);
}

void test_str_reverse() {
  Str* str = str_new("Hello, World!");
  assert(str);
  str_reverse(str);
  printf("Reversed string: %s\n", str_data(str));
  assert(strcmp(str_data(str), "!dlroW ,olleH") == 0);

  str_free(str);
}

void test_str_startswith() {
  Str* str = str_new("Hello, World!");
  assert(str);
  int result1 = str_startswith(str, "Hello");
  int result2 = str_startswith(str, "World");
  printf("Starts with 'Hello': %d\n", result1);
  printf("Starts with 'World': %d\n", result2);
  assert(result1 == 1);
  assert(result2 == 0);

  str_free(str);
}

void test_str_endswith() {
  Str* str = str_new("Hello, World!");
  assert(str);
  int result1 = str_endswith(str, "World!");
  int result2 = str_endswith(str, "Hello");
  printf("Ends with 'World!': %d\n", result1);
  printf("Ends with 'Hello': %d\n", result2);
  assert(result1 == 1);
  assert(result2 == 0);

  str_free(str);
}

// sudo apt-get install libpcre3-dev
void test_regex_sub_match() {
  const char* str1   = "Hello, World!";
  const char* regex1 = "Hello, (\\w+)!";
  int capture_group1 = 1;
  char* sub_match1   = regex_sub_match(str1, regex1, capture_group1);
  assert(sub_match1 != NULL);
  assert(strcmp(sub_match1, "World") == 0);
  free(sub_match1);

  const char* str2   = "Hello, OpenAI!";
  const char* regex2 = "Hello, (\\w+)!";
  int capture_group2 = 1;
  char* sub_match2   = regex_sub_match(str2, regex2, capture_group2);
  assert(sub_match2 != NULL);
  assert(strcmp(sub_match2, "OpenAI") == 0);
  free(sub_match2);

#ifdef USE_PCRE_REGEX
  printf("Testing PCRE Regex syntax\n");

  const char* str3   = "Hello, 123!";
  const char* regex3 = "Hello, (\\d+)!";

  int capture_group3 = 1;
  char* sub_match3   = regex_sub_match_pcre(str3, regex3, capture_group3);
  assert(sub_match3 != NULL);
  assert(strcmp(sub_match3, "123") == 0);
  free(sub_match3);
#endif
}

void test_regex_sub_matches_pcre() {
#ifdef USE_PCRE_REGEX
  const char* str   = "Hello, World! How are you?";
  const char* regex = "([a-zA-Z]+), ([a-zA-Z]+)! (\\w+) (\\w+) ([a-zA-Z\?]+)";

  int num_capture_groups = 6;
  int num_matches;

  char** sub_matches = regex_sub_matches_pcre(str, regex, num_capture_groups, &num_matches);
  if (sub_matches == NULL) {
    printf("No matches found\n");
    return;
  }

  printf("Number of matches: %d\n", num_matches);
  for (int i = 0; i < num_matches; i++) {
    printf("Match %d:\n", i + 1);
    for (int j = 0; j < num_capture_groups; j++) {
      printf("  Group %d: %s\n", j + 1, sub_matches[i * num_capture_groups + j]);
      free(sub_matches[i * num_capture_groups + j]);
    }
    printf("\n");
  }
  free(sub_matches);

#endif
}

// sudo apt-get install libpcre3-dev
// gcc -g str_test.c str.c -Wall -Werror -DUSE_PCRE_REGEX -lpcre2-8 && ./a.out

void test_string_allocation_in_arena() {
  arena_t* arena = arena_create(1024);
  Str* str       = str_new_witharena("Hello World my dear friends", arena);

  printf("arena_str: %s\n", str_data(str));
  arena_free(arena);
}

int main() {
  test_string_allocation_in_arena();
  test_str_new();
  test_str_compare();
  test_str_copy();
  test_str_concat();
  test_str_length();
  test_str_at();
  test_str_contains();
  test_str_is_empty();
  test_str_find();
  test_str_replace();
  test_str_to_upper();
  test_str_to_lower();
  test_str_split();
  test_str_match();
  test_str_replace_all();
  test_str_to_camel_case();
  test_str_to_title_case();
  test_str_to_snake_case();

  test_str_insert();  // failure
  test_str_split_max();

  test_str_remove();
  test_str_join();
  test_str_substring();
  test_str_reverse();
  test_str_startswith();
  test_str_endswith();
  test_regex_sub_match();
  test_regex_sub_matches_pcre();

  return 0;
}
