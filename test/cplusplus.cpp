/**
 * @file cplusplus.cpp Emulate C++ applications
 *
 * Copyright (C) 2025 Alfred E. Heggestad
 */

#include <iostream>
#include <re_atomic.h>
#include <re.h>
#include "test.h"


#define DEBUG_MODULE "cplusplus"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


int test_cplusplus(void)
{
	std::cout << "test\n";

	DEBUG_NOTICE("%H\n", sys_kernel_get, nullptr);

	return 0;
}
