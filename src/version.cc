#include "ed.h"
#include "cdecl.h"
#include "version.h"
#include "version-describe.gen.h"

#if !PROGRAM_PATCH_LEVEL
# if !PROGRAM_MINOR_REVISION
#  if !PROGRAM_MAJOR_REVISION
#   define PROGRAM_VERSION \
  _TOSTR (PROGRAM_MAJOR_VERSION) "." _TOSTR (PROGRAM_MINOR_VERSION)
#  else /* PROGRAM_MAJOR_REVISION */
#   define PROGRAM_VERSION \
  _TOSTR (PROGRAM_MAJOR_VERSION) "." _TOSTR (PROGRAM_MINOR_VERSION) \
    "." _TOSTR (PROGRAM_MAJOR_REVISION)
#  endif /* PROGRAM_MAJOR_REVISION */
# else /* PROGRAM_MINOR_REVISION */
#  define PROGRAM_VERSION \
  _TOSTR (PROGRAM_MAJOR_VERSION) "." _TOSTR (PROGRAM_MINOR_VERSION) \
    "." _TOSTR (PROGRAM_MAJOR_REVISION) "." _TOSTR (PROGRAM_MINOR_REVISION)
# endif /* PROGRAM_MINOR_REVISION */
#else /* PROGRAM_PATCH_LEVEL */
#  define PROGRAM_VERSION \
  _TOSTR (PROGRAM_MAJOR_VERSION) "." _TOSTR (PROGRAM_MINOR_VERSION) \
    "." _TOSTR (PROGRAM_MAJOR_REVISION) "." _TOSTR (PROGRAM_MINOR_REVISION) \
      "." _TOSTR (PROGRAM_PATCH_LEVEL)
#endif /* PROGRAM_PATCH_LEVEL */

#if defined(PROGRAM_VERSION_DESCRIBE_STRING)
# define DISPLAY_VERSION_STRING PROGRAM_VERSION_DESCRIBE_STRING
#else
# define DISPLAY_VERSION_STRING PROGRAM_VERSION
#endif

#define TITLEBAR_STRING PROGRAM_NAME " " DISPLAY_VERSION_STRING

char TitleBarString[TITLE_BAR_STRING_SIZE] = TITLEBAR_STRING;
const char VersionString[] = PROGRAM_VERSION;
const char DisplayVersionString[] = DISPLAY_VERSION_STRING;
const char ProgramName[] = PROGRAM_NAME;
const char ProgramNameWithVersion[] = PROGRAM_NAME " version " PROGRAM_VERSION;
const char ProgramAppUserModelId[] = PROGRAM_APP_USER_MODEL_ID;
