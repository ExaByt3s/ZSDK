#include "common/rl_kernel.h"


#include "common/mem.h"

#if defined _WIN64
#  define ADVANCED_ALLOC_BYTES 8
#else
#  define ADVANCED_ALLOC_BYTES 4
#endif

static HANDLE mainHeap;
static bool heapCreated;


namespace Mem
{



	void init()
	{
		mainHeap = CWA(kernel32, HeapCreate)(0, 0, 0);
		if (mainHeap == NULL)
		{
			mainHeap = CWA(kernel32, GetProcessHeap)();
			heapCreated = false;
		}
		else heapCreated = true;
	}

	void uninit(void)
	{
		if (heapCreated)
		CWA(kernel32, HeapDestroy)(mainHeap);
	}

	bool reallocEx(void* old, SIZE_T size)
	{
		if (size == 0)
		{
			free(*(LPBYTE *)old);
			*(LPBYTE *)old = NULL;
		}
		else
		{
			register void* p = realloc(*(LPBYTE *)old, size);
			if (p == NULL)return false;
			*(LPBYTE *)old = (LPBYTE)p;
		}

		return true;
	}

	void* realloc(void* old, SIZE_T size)
	{
		if (size == 0)return NULL;


		size += ADVANCED_ALLOC_BYTES;


		if (old == nullptr)
			old = CWA(kernel32, HeapAlloc)(mainHeap, HEAP_ZERO_MEMORY, size);
		else
			old = CWA(kernel32, HeapReAlloc)(mainHeap, HEAP_ZERO_MEMORY, old, size);

		return old;
	}

	void* alloc(SIZE_T size)
	{
		register void* p;

		if (size == 0)p = NULL;
		else
		{
			size += ADVANCED_ALLOC_BYTES;
			p = CWA(kernel32, HeapAlloc)(mainHeap, HEAP_ZERO_MEMORY, size);
		}
		return p;
	}

	void* quickAlloc(SIZE_T size)
	{
		register void* p;

		if (size == 0)p = NULL;
		else
		{
			size += ADVANCED_ALLOC_BYTES;
			p = CWA(kernel32, HeapAlloc)(mainHeap, 0, size);
		}
		return p;
	}

	void free(void* mem)
	{
		if (mem)
		CWA(kernel32, HeapFree)(mainHeap, 0, mem);
	}

	void zeroAndFree(void* mem, SIZE_T size)
	{
		_zero(mem, size);
		free(mem);
	}

	void freeArrayOfPointers(void* mem, SIZE_T count)
	{
		if (mem && count)
		{
			LPBYTE* p = (LPBYTE *)mem;
			while (count--)free(p[count]);
			free(p);
		}
	}

	void _copy(void* dest, const void* source, SIZE_T size)
	{
		for (SIZE_T i = 0; i < size; i++)
		{
			((LPBYTE)dest)[i] = ((LPBYTE)source)[i];
			if (i == 0)i = 0;
		}
	}

	void _copyFromEnd(void* dest, const void* source, SIZE_T size)
	{
		while (size--)
			((LPBYTE)dest)[size] = ((LPBYTE)source)[size];
	}

	void* _copy2(void* dest, const void* source, SIZE_T size)
	{
		_copy(dest, source, size);
		return (void *)((LPBYTE)dest + size);
	}

	void* copyEx(const void* source, SIZE_T size)
	{
		void* p = quickAlloc(size);
		if (p != NULL)_copy(p, source, size);
		return p;
	}

	int _compare(const void* mem1, const void* mem2, SIZE_T size)
	{
		register BYTE m1, m2;
		for (register SIZE_T i = 0; i < size; i++)
		{
			m1 = ((LPBYTE)mem1)[i];
			m2 = ((LPBYTE)mem2)[i];
			if (m1 != m2)return (int)(m1 - m2);
		}
		return 0;
	}

	void _zero(void* mem, SIZE_T size)
	{
		_set(mem, 0, size);
	}

	void _set(void* mem, char c, SIZE_T size)
	{
		SIZE_T i = size;
		while (i--)((char *)mem)[i] = c;
	}

	void* _getL(void* mem, char c, SIZE_T size)
	{
		for (SIZE_T i = 0; i < size; i++)
			if (((char *)mem)[i] == c)return ((char *)mem) + i;

		return nullptr;
	}

	void* _getR(void* mem, char c, SIZE_T size)
	{
		SIZE_T i = size;
		while (i--)
			if (((char *)mem)[i] == c)return ((char *)mem) + i;

		return nullptr;
	}

	void _replace(void* mem, SIZE_T size, char oldChar, char newChar)
	{
		for (register SIZE_T i = 0; i < size; i++)if (((char *)mem)[i] == oldChar)((char *)mem)[i] = newChar;
	}

	void* _findData(const void* mem, SIZE_T memSize, void* data, SIZE_T dataSize)
	{
		if (memSize >= dataSize)
		{
			memSize -= dataSize;

			for (register SIZE_T i = 0; i <= memSize; i++)
			{
				register LPBYTE p = (LPBYTE)mem + i;
				if (_compare(p, data, dataSize) == 0)return (void *)p;
			}
		}
		return NULL;
	}

	void _swap(void* mem1, void* mem2, SIZE_T size)
	{
		BYTE tmp;
		LPBYTE b1 = (LPBYTE)mem1;
		LPBYTE b2 = (LPBYTE)mem2;

		if (mem1 != mem2)
			while (size--)
			{
				tmp = *b1;
				*b1++ = *b2;
				*b2++ = tmp;
			}
	}

	SIZE_T _replaceDword(DWORD originalValue, DWORD newValue, void* mem, SIZE_T memSize)
	{
		SIZE_T count = 0;
		if (memSize >= sizeof(DWORD))
		{
			memSize -= sizeof(DWORD);
			for (SIZE_T i = 0; i <= memSize; i++)
			{
				LPDWORD p = (LPDWORD)((LPBYTE)mem + i);
				if (*p == originalValue)
				{
					count++;
					*p = newValue;
					i += sizeof(DWORD);
				}
			}
		}
		return count;
	}

	SIZE_T _replaceQword(DWORD64 originalValue, DWORD64 newValue, void* mem, SIZE_T memSize)
	{
		SIZE_T count = 0;
		if (memSize >= sizeof(DWORD64))
		{
			memSize -= sizeof(DWORD64);
			for (SIZE_T i = 0; i <= memSize; i++)
			{
				DWORD64* p = (DWORD64 *)((LPBYTE)mem + i);
				if (*p == originalValue)
				{
					count++;
					*p = newValue;
					i += sizeof(DWORD64);
				}
			}
		}
		return count;
	}


}
