#ifndef _GDB_REMOTE_H_
#define _GDB_REMOTE_H_

/*
 * Packets are indicated by their first character, which is a char,
 * so there are 256 potential characters.
 */
#define NUM_PACKETS (256)

int gdb_send_packet(int fd, char* data);
int gdb_recv_packet(int fd, char** buffer);
int gdb_check_for_interrupt(int fd);

#endif
