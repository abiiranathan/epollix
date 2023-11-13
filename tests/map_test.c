#include "../http/map.h"

typedef char* string;

// Example usage:
DECLARE_HASHMAP(int, string);

int main() {
  // Create a hashmap with int keys and string values
  HashMap_int_string* myMap = create_int_string_map(10);

  // Test insert and get functions
  insert_int_string(myMap, 1, "One");
  insert_int_string(myMap, 2, "Two");
  insert_int_string(myMap, 3, "Three");

  assert(strcmp(*get_int_string(myMap, 1), "One") == 0);
  assert(strcmp(*get_int_string(myMap, 2), "Two") == 0);
  assert(strcmp(*get_int_string(myMap, 3), "Three") == 0);
  assert(get_int_string(myMap, 4) == NULL);  // Non-existent key

  // Test delete function
  delete_int_string(myMap, 2);
  assert(get_int_string(myMap, 2) == NULL);

  // Test clear function
  clear_int_string_map(myMap);
  assert(get_int_string(myMap, 1) == NULL);
  assert(get_int_string(myMap, 3) == NULL);

  // Test keys and values functions
  insert_int_string(myMap, 5, "Five");
  insert_int_string(myMap, 6, "Six");
  insert_int_string(myMap, 7, "Seven");

  int* keys     = keys_int_string_map(myMap);
  char** values = values_int_string_map(myMap);

  assert(keys[0] == 5);
  assert(keys[1] == 6);
  assert(keys[2] == 7);

  assert(strcmp(values[0], "Five") == 0);
  assert(strcmp(values[1], "Six") == 0);
  assert(strcmp(values[2], "Seven") == 0);

  // Clean up
  free(keys);
  free(values);
  destroy_int_string_map(myMap);

  printf("All tests passed!\n");

  return 0;
}
