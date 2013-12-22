/*
 * io.c - 
 */

#include <io.h>

#include <types.h>

/**************/
/** Screen  ***/
/**************/

#define NUM_COLUMNS 80
#define NUM_ROWS    25

Byte x, y=15;

/* Read a byte from 'port' */
Byte inb (unsigned short port)
{
  Byte v;

  __asm__ __volatile__ ("inb %w1,%0":"=a" (v):"Nd" (port));
  return v;
}

void printblank()
{
    if (++x >= NUM_COLUMNS) x = 0;
    char c = ' ';
    __asm__ __volatile__ ( "movb %0, %%al; outb $0xe9" ::"a"(c));
    Word ch = (Word) (c & 0x00FF) | 0x0200;
    DWord screen = 0xb8000 + (y * NUM_COLUMNS + x) * 2;
    asm("movw %0, (%1)" : : "g"(ch), "g"(screen));
}


void printc(char c)
{
     __asm__ __volatile__ ( "movb %0, %%al; outb $0xe9" ::"a"(c));
  if (c=='\n')
  {
    x = 0;
    y=(y+1)%NUM_ROWS;
    int i;
    for (i = 0; i < 80; i++) printblank();
  }
  else
  {
    Word ch = (Word) (c & 0x00FF) | 0x0200;
    DWord screen = 0xb8000 + (y * NUM_COLUMNS + x) * 2;
    if (++x >= NUM_COLUMNS)
    {
      x = 0;
      y=(y+1)%NUM_ROWS;
      int i;
      for (i = 0; i < 80; i++) printblank();
    }
    asm("movw %0, (%1)" : : "g"(ch), "g"(screen));
  }
}

void printc_xy(Byte mx, Byte my, char c)
{
  Byte cx, cy;
  cx=x;
  cy=y;
  x=mx;
  y=my;
  printc(c);
  x=cx;
  y=cy;
}

void printk(char *string)
{
  int i;
  for (i = 0; string[i]; i++)
    printc(string[i]);
}
