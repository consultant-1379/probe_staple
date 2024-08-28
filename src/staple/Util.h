#ifndef UTIL_H
#define UTIL_H

#include <ostream>
#include <string>
#include <time.h>

struct timeval AbsTimeDiff (const struct timeval&, const struct timeval&);

typedef void (*config_single_callback)(std::string const&, std::string const&, void*);

/**
 * Parse possibly multi-line configuration using callback for each key/value pair
 * and log any problems if ostream is given.
 */
void config_real(std::string const&, config_single_callback, void*, std::ostream *&);

unsigned int parseint(std::string const&) throw (std::string);
double parsedbl(std::string const&) throw (std::string);

#endif
