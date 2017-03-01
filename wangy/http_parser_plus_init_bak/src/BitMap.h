#ifndef __BIT_MAP_H
#define __BIT_MAP_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>

using namespace std;

#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)


#define MAX_BMAP_WIDTH         128
#define MAX_BYTE_BMAP          (MAX_BMAP_WIDTH/8)

class ClsBMap{
private:
	unsigned char      BitMap[MAX_BYTE_BMAP];

public:
	ClsBMap();
	~ClsBMap();

	bool operator==(const ClsBMap & s)
	{
		if (memcmp(this->BitMap, s.BitMap, sizeof(this->BitMap)))
		{
			return false;
		}
		else
		{
			return true;
		}
	}

	void reset();
	void setall();
	bool getbit(int index);
	void setbit(int index);
	void resetbit(int index);
	void display(void);
	string getmap(void);
	
};

#endif
