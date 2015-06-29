#include "properties.h"
#include <fstream>
#include <Common/util.h>
#include <sstream>
#include <string>
#include <stdexcept>

std::string trim(std::string s)
{
  size_t start = 0, end = s.length();
  while(s[start] == ' ' && start < end) start++;
  while(s[end-1] == ' ' && start < end) end--;
  return s.substr(start,end);
}

properties_t::properties_t()
{
}

properties_t::properties_t(const char* filename)
{
  if(read_file(filename) < 0)
    throw new std::runtime_error(std::string("Could not open properties file ")+filename+"!");
}

int properties_t::read_file(const char* filename)
{
  std::ifstream in(filename);
  if(!in)
    return -1;

  std::string line;
  while(std::getline(in,line))
  {
    size_t pos;
    if((pos = line.find('#')) != std::string::npos)
      line = line.substr(0,pos);

    if((pos = line.find('=')) != std::string::npos)
    {
      std::string key = trim(line.substr(0,pos));
      std::string value = trim(line.substr(pos+1));

      props[key] = value;
    }
    else if(line.substr(0,8) == "include ")
    {
      std::string oldfile = trim(filename);
      std::string newfile = trim(line.substr(8)).c_str();
      if(newfile.length())
      {
        if(newfile[0] != '/' && (pos = oldfile.rfind('/')) != std::string::npos)
          newfile = oldfile.substr(0,pos+1) + newfile;
        read_file(newfile.c_str());
      }
    }
  }

  return 0;
}

std::string properties_t::get_string(const char* key, const char* alt) const
{
  std::map<std::string,std::string>::const_iterator i = props.find(key);
  if(i == props.end())
  {
    if(alt != NULL)
      return alt;
    warn("Properties file does not contain key %s!",key);
    return "";
  }
  return i->second;
}

long long properties_t::get_int(const char* key, long long alt) const
{
  if(alt != LLONG_MIN && !has_key(key))
    return alt;

  std::string value = get_string(key);
  long long i = 0;
  if(value.substr(0,2) == "0x")
    std::istringstream(value.substr(2)) >> std::hex >> i;
  else
    std::istringstream(value) >> std::dec >> i;
  return i;
}

void properties_t::set_int(const char* key, long long i)
{
  std::ostringstream os;
  os << i;
  set_string(key,os.str());
}

void properties_t::set_string(const char* key, const std::string& s)
{
  props[key] = s;
}

bool properties_t::has_key(const char* key) const
{
  return props.find(key) != props.end();
}
