#ifndef _PROPERTIES_H
#define _PROPERTIES_H

#include <map>
#include <string>
#include <limits.h>

class properties_t
{
public:
  properties_t();
  properties_t(const char* filename);

  int read_file(const char* filename);
  std::string get_string(const char* name, const char* alt = NULL) const;
  long long get_int(const char* name, long long alt = LLONG_MIN) const;
  bool has_key(const char* name) const;
  void set_int(const char* name, long long i);
  void set_string(const char* name, const std::string& s);

private:
  std::map<std::string,std::string> props;
};

#endif
