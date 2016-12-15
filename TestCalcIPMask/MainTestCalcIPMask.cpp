#include<stdio.h>
#include<stdlib.h>
#include<string>
#include<strings.h>

using namespace std;


long long bitPower(int power)
{
	if (power < 0 || power > 63)
		return -1;
	else
		return 0x01L << power;
}

unsigned int maskBit2MaskUint(int maskbit)
{
	unsigned int allmask = 0xFFFFFFFF;

	unsigned int realmask = allmask  << (32 - maskbit);

	return realmask;
}

string IPRangeToMask(unsigned int beginip, unsigned int endip)
{
	unsigned int allmask = 0xFFFFFFFF;
	unsigned int startmask = allmask;
	unsigned int tempmask = 0;

	unsigned int startip = beginip;
	unsigned int tempEnd = 0;
	string result = "";

	// 对每个地址进行判断处理
	while(startip < endip)
	{
		int i = 0;
		// 判断每个地址的各bit位
		for (i = 0; i < 32; i++)
		{
			// 对32个bit位中的每个bit位，算出一个掩码
			tempmask = (startmask << i) & allmask;

			if ( ((startip & tempmask) < startip) || ((startip | (allmask - tempmask)) > endip) )
			{
				printf("i = %d\n", i);
				tempmask = maskBit2MaskUint(32 - i + 1);

				char strip[32], strmask[32];
				bzero(strip, sizeof(strip));
				bzero(strmask, sizeof(strmask));
				sprintf(strip, "%u", startip);
				sprintf(strmask, "%u", tempmask);

				result = result + strip + "," + strmask + ";";
				tempEnd = startip + allmask - tempmask;
				printf("End ip of current range, endip = %u\n", tempEnd);
				startip += bitPower(i - 1);
				printf("next ip range, startip = %u\n", startip);

				break;
			}
		}
	}

	if (startip == endip)
	{
		tempmask = maskBit2MaskUint(32);
		printf("single ip range, startip == endip = %u\n", startip);
	}


	return result;
}

int main(int argc, char **argv)
{
	IPRangeToMask(173616385, 173616394);
	//printf("========================\n%s\n", IPRangeToMask(3232235520, 3232235778).c_str());
	//printf("========================\n%s\n", IPRangeToMask(173616385, 173616394).c_str());
	exit(1);

	printf("maskBit2MaskUint(8) = %u\n", maskBit2MaskUint(8));
	printf("maskBit2MaskUint(16) = %u\n", maskBit2MaskUint(16));
	printf("maskBit2MaskUint(22) = %u\n", maskBit2MaskUint(22));

	printf("bitPower(0) = %lld\n", bitPower(0)); 
	printf("bitPower(1) = %lld\n", bitPower(1)); 
	printf("bitPower(2) = %lld\n", bitPower(2)); 
	printf("bitPower(8) = %lld\n", bitPower(8)); 
	printf("bitPower(16) = %lld\n", bitPower(16));

	return 0;
}
