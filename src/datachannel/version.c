/**
 * @file version.c WebRTC data-channel companion API version
 *
 * Copyright (C) 2026 The baresip project
 */

#include <re_datachannel.h>


uint32_t dc_api_version_1(void)
{
	return RE_DATACHANNEL_API_VERSION;
}
