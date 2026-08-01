#include <re_datachannel.h>

int main(void)
{
	return dc_api_version_1() == RE_DATACHANNEL_API_VERSION ? 0 : 1;
}
