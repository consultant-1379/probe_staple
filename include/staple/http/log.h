#ifndef LOG_H
#define LOG_H

#include <iostream>
#include <sstream>

#include <staple/Staple.h>
#include "Counter.h"

/* We log if HttpLogLevel <= Staple::logLevel. */
enum HttpLogLevel {HTTP_LOG_LEVEL_ERROR = 0,
		   HTTP_LOG_LEVEL_WARN = 3,
		   HTTP_LOG_LEVEL_INFO = 4,
		   HTTP_LOG_LEVEL_DEBUG = 5};

#define LOG_TEMPLATE_TYPES typename C1, \
		typename C2 = const char*, \
		typename C3 = const char*, \
		typename C4 = const char*, \
		typename C5 = const char*, \
		typename C6 = const char*, \
		typename C7 = const char*, \
		typename C8 = const char*, \
		typename C9 = const char*, \
		typename C10 = const char*

#define LOG_TEMPLATE_ARGS const C1& x1, \
		const C2& x2 = "", \
		const C3& x3 = "", \
		const C4& x4 = "", \
		const C5& x5 = "", \
		const C6& x6 = "", \
		const C7& x7 = "", \
		const C8& x8 = "", \
		const C9& x9 = "", \
		const C10& x10 = ""

#define LOG_ARGS x1, x2, x3, x4, x5, x6, x7, x8, x9, x10

template<
typename C1,
typename C2,
typename C3,
typename C4,
typename C5,
typename C6,
typename C7,
typename C8,
typename C9,
typename C10
>
	void httpPrint(Staple& staple,
		       enum HttpLogLevel level,
		       const C1& x1,
		       const C2& x2,
		       const C3& x3,
		       const C4& x4,
		       const C5& x5,
		       const C6& x6,
		       const C7& x7,
		       const C8& x8,
		       const C9& x9,
		       const C10& x10
		)
{
	const char* prefix;
	if (level > staple.logLevel)
		return;

	switch (level) {
	case HTTP_LOG_LEVEL_ERROR: prefix = "HTTP Error "; break;
	case HTTP_LOG_LEVEL_WARN: prefix = "HTTP Warning "; break;
	case HTTP_LOG_LEVEL_INFO: prefix = "HTTP "; break;
	default: prefix = "HTTP debug ";
	}
	staple.logStream << prefix << x1 << x2 << x3 << x4 << x5 << x6 << x7 << x8 << x9 << x10 << std::endl;
}



template< LOG_TEMPLATE_TYPES > void error(Staple& staple, LOG_TEMPLATE_ARGS )
{
	httpPrint(staple, HTTP_LOG_LEVEL_ERROR, LOG_ARGS);
}

template< LOG_TEMPLATE_TYPES > void warn(Staple& staple, LOG_TEMPLATE_ARGS )
{
	httpPrint(staple, HTTP_LOG_LEVEL_WARN, LOG_ARGS);
}

template< LOG_TEMPLATE_TYPES > void log(Staple& staple, LOG_TEMPLATE_ARGS )
{
	httpPrint(staple, HTTP_LOG_LEVEL_INFO, LOG_ARGS);
}

template< LOG_TEMPLATE_TYPES > void debug(Staple& staple, LOG_TEMPLATE_ARGS )
{
	httpPrint(staple, HTTP_LOG_LEVEL_DEBUG, LOG_ARGS);
}

template< LOG_TEMPLATE_TYPES > void logStderr( LOG_TEMPLATE_ARGS )
{
	std::cerr << x1 << x2 << x3 << x4 << x5 << x6 << x7 << x8 << x9 << x10 << std::endl;
}
#undef LOG_TEMPLATE_TYPES
#undef LOG_TEMPLATE_ARGS
#undef LOG_ARGS

/* Formatting the arguments can be somewhat expensive (e.g.,
 * quoteString is used frequently). Instead of calling log and warn
 * directly we check if they will log anything with shouldLog
 * first. Hence, we avoid the formatting overhead when only counting.
 */
#define LOG_AND_COUNT(str, ...)					\
	do {							\
		COUNTER_INCREASE(str);				\
		if (HTTP_LOG_LEVEL_INFO <= staple_.logLevel)	\
			log(staple_, str, ##__VA_ARGS__);	\
	} while(0)

#define WARN(str, ...)						\
	do {							\
		COUNTER_INCREASE(str);				\
		if (HTTP_LOG_LEVEL_WARN <= staple_.logLevel)	\
			warn(staple_, str, ##__VA_ARGS__);	\
	} while(0)

#endif
