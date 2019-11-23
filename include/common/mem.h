#pragma once

typedef struct
{
  void *data;
  SIZE_T size;
}MEMDATA;

#define OFFSETOF(v, m)  ((DWORD_PTR)(&((v *)(NULL))->m))


#define ALIGN_DOWN(x, align)  ((x) & ~(align - 1))
#define ALIGN_UP(x, align) (((x) & (align - 1)) ? ALIGN_DOWN(x, align) + align : (x))

#define VM_PAGE_SIZE 4096

#define VM_STEP_MASK (~0xFFFF)
#define VM_STEP      0x10000

namespace Mem
{


  void init();

  void uninit(void);
  
  bool reallocEx(void *old, SIZE_T size);

  void *realloc(void *old, SIZE_T size);

  void *alloc(SIZE_T size);

  void *quickAlloc(SIZE_T size);

  void free(void *mem);

  void zeroAndFree(void *mem, SIZE_T size);

  void freeArrayOfPointers(void *mem, SIZE_T count);

  void  _copy(void *dest, const void *source, SIZE_T size);

  void _copyFromEnd(void *dest, const void *source, SIZE_T size);

  void *_copy2(void *dest, const void *source, SIZE_T size);

  void *copyEx(const void *source, SIZE_T size);

  int _compare(const void *mem1, const void *mem2, SIZE_T size);

  void _zero(void *mem, SIZE_T size);

  void  _set(void *mem, char c, SIZE_T size);

  void *_getL(void *mem, char c, SIZE_T size);

  void *_getR(void *mem, char c, SIZE_T size);

  void _replace(void *mem, SIZE_T size, char oldChar, char newChar);

  void *_findData(const void *mem, SIZE_T memSize, void *data, SIZE_T dataSize);

  void _swap(void *mem1, void *mem2, SIZE_T size);

  SIZE_T _replaceDword(DWORD originalValue, DWORD newValue, void *mem, SIZE_T memSize);

  SIZE_T _replaceQword(DWORD64 originalValue, DWORD64 newValue, void *mem, SIZE_T memSize);
};
