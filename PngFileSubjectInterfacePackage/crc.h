#pragma once

unsigned long update_crc(unsigned long crc, unsigned char *buf, int len);
unsigned long crc(unsigned char *buf, int len);

unsigned long crc_init();
unsigned long crc_finish(unsigned long crc);