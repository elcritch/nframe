#include <stdio.h>

extern void nframe_entry_build(void);

static void cdeep0(void) { nframe_entry_build(); }
static void cdeep1(void) { cdeep0(); }
static void cdeep2(void) { cdeep1(); }
static void cdeep3(void) { cdeep2(); }
static void cdeep4(void) { cdeep3(); }
static void cdeep5(void) { cdeep4(); }
static void cdeep6(void) { cdeep5(); }
void cdeep7(void) { cdeep6(); }

