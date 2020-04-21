#ifndef __POLYTRACKER_H__
#define __POLYTRACKER_H__

#define POLYTRACKER_VERSION_MAJOR    1
#define POLYTRACKER_VERSION_MINOR    0
#define POLYTRACKER_VERSION_REVISION 1

// Set the version note to an empty string if there is no note
#define POLYTRACKER_SUFFIX     "alpha2.2"

/**********************************************************************************/

#define PF_STR_HELPER(s) #s
#define PF_MAKE_STR(s) PF_STR_HELPER(s)

#define POLYTRACKER_VERSION PF_MAKE_STR(POLYTRACKER_VERSION_MAJOR) "." PF_MAKE_STR(POLYTRACKER_VERSION_MINOR) "." PF_MAKE_STR(POLYTRACKER_VERSION_REVISION)

#endif
