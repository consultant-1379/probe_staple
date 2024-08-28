#ifndef BOOST_REIMPLEMENTATION
#define BOOST_REIMPLEMENTATION

/* This file contains reimplementations of some functions in boost.
 *
 * We avoid a dependency on boost as it is a large piece of code that
 * may be difficult to install in some places.
 */

bool iends_with(const char* s, const char* test);
bool starts_with(const char* s, const char* test);
bool iequals(const char* s1, const char* s2);

#endif
