
#include "BitMap.h"

ClsBMap::ClsBMap()
{
	this->reset();
}

ClsBMap::~ClsBMap()
{
}

void ClsBMap::reset()
{
	memset(this->BitMap, 0, sizeof(this->BitMap));
}

void ClsBMap::setall()
{
	memset(this->BitMap, 0xFF, sizeof(this->BitMap));
}

bool ClsBMap::getbit(int index)
{
	int remainder = index & 0x7;
	int quotient = index >> 3;

	return this->BitMap[quotient] & (0x01 << remainder);
}

void ClsBMap::setbit(int index)
{
	int remainder = index & 0x7;
	int quotient = index >> 3;
	
	this->BitMap[quotient] |= (0x1 << remainder);
}

void ClsBMap::resetbit(int index)
{
	int remainder = index & 0x7;
	int quotient = index >> 3;
	
	this->BitMap[quotient] &= (~(0x01 << remainder));
}

void ClsBMap::display(void)
{
	for (int i = 0; i < sizeof(this->BitMap); i++)
	{
		printf("%02X ", this->BitMap[i]);
	}
	printf("\n");
}

string ClsBMap::getmap(void)
{
	string str_BMap("");
	char   str_byte[8];

	for (int i = 0; i < sizeof(this->BitMap); i++)
	{
		//printf("%02X ", this->BitMap[i]);
		bzero(str_byte, sizeof(str_byte));
		snprintf(str_byte, sizeof(str_byte) - 1, "%02X", this->BitMap[i]);

		str_BMap.append(str_byte);
	}

	return str_BMap;
}
