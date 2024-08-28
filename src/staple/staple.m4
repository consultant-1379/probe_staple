# SYNOPSIS
#
#   AX_STAPLE
#
# DESCRIPTION
#
#   Test for the libstaple library and header file.
#
#   If no path to the library is given the macro searches under /usr/lib and
#   /usr/local/lib.
#
#   This macro calls:
#
#     AC_SUBST(LIBSTAPLE_CPPFLAGS)
#     AC_SUBST(LIBSTAPLE_LDFLAGS)
#
#   and sets:
#
#     HAVE_LIBSTAPLE
#
# LICENSE
#
#   Copyright (C) 2011 Ericsson AB
#
#   Copying and distribution of this file, with or without modification, are
#   permitted in any medium without royalty provided the copyright notice
#   and this notice are preserved. This file is offered as-is, without any
#   warranty.

AC_DEFUN([AX_STAPLE],
[
AC_ARG_WITH([staple],
            [AS_HELP_STRING([--with-staple@<:@=DIR@:>@],
                            [build Staple module using libstaple in DIR or standard places @<:@default: no@:>@])],
            [
              want_staple="yes"
              if test "x$withval" = "x"; then
                ac_staple_path=""
              else
                ac_staple_path="$withval"
              fi
            ],
            [want_staple="no"])

if test "x$want_staple" = "xyes"; then
  AC_MSG_CHECKING([for libstaple])
  staple_ok="no"
  if test "x$ac_staple_path" = "x"; then
    for ac_staple_path_tmp in /usr/lib /usr/local/lib; do
      if ls "$ac_staple_path_tmp/libstaple"* >/dev/null 2>&1; then
        ac_staple_path="$ac_staple_path_tmp"
        break
      fi
    done
  fi
  LIBSTAPLE_CPPFLAGS="-I$ac_staple_path"
  LIBSTAPLE_LDFLAGS="-L$ac_staple_path -lstaple"
  save_ldflags=$LDFLAGS
  save_cppflags=$CPPFLAGS
  LDFLAGS="$LDFLAGS $LIBSTAPLE_LDFLAGS"
  CPPFLAGS="$CPPFLAGS $LIBSTAPLE_CPPFLAGS"
  export CPPFLAGS LDFLAGS
  AC_REQUIRE([AC_PROG_CXX])
  AC_LANG_PUSH([C++])
  AC_LINK_IFELSE(
    [AC_LANG_PROGRAM([[
         @%:@include "StapleAPI.h"
       ]], [[
         std::string s = staple::libstaple_version@{:@@:}@;
       ]])],
    [AC_MSG_RESULT([found])
     staple_ok="yes"],
    [AC_MSG_RESULT([not found])]
  )
  AC_LANG_POP([C++])
  LDFLAGS=$save_ldflags
  CPPFLAGS=$save_cppflags
  if test "$staple_ok" = "yes"; then
    AC_DEFINE([HAVE_LIBSTAPLE],,[define if libstaple is available])
    AC_SUBST([LIBSTAPLE_CPPFLAGS])
    AC_SUBST([LIBSTAPLE_LDFLAGS])
  else
    AC_MSG_FAILURE([--with-staple was given but test for libstaple failed])
  fi
fi
])
