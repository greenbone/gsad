# Copyright (C) 2018-2021 Greenbone AG
#
# SPDX-License-Identifier: AGPL-2.0-or-later

# This script attempts to determine the Git commit ID

find_package(Git)

macro(git_get_revision dir variable)
  if(GIT_FOUND)
    execute_process(
      COMMAND ${GIT_EXECUTABLE} rev-parse --abbrev-ref HEAD
      WORKING_DIRECTORY ${dir}
      ERROR_QUIET
      RESULT_VARIABLE GIT_RESULT
      OUTPUT_VARIABLE GIT_BRANCH
      OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    if(GIT_RESULT EQUAL "0")
      execute_process(
        COMMAND ${GIT_EXECUTABLE} log -1 --format=%h
        WORKING_DIRECTORY ${dir}
        OUTPUT_VARIABLE GIT_COMMIT_HASH
        OUTPUT_STRIP_TRAILING_WHITESPACE
      )
      string(REPLACE "/" "_" GIT_BRANCH ${GIT_BRANCH})
      set(${variable} "${GIT_COMMIT_HASH}-${GIT_BRANCH}")
    endif()
  endif()
endmacro()
