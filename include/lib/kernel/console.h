#ifndef __LIB_KERNEL_CONSOLE_H
#define __LIB_KERNEL_CONSOLE_H

void console_init (void);
void console_panic (void);
void console_print_stats (void);

// add
void putbuf (const char *buffer, long unsigned int n);

#endif /* lib/kernel/console.h */
