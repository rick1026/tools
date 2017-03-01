#ifndef __MWM_H__
#define __MWM_H__

#ifndef WIN32

#ifndef INLINE
#define INLINE inline
#endif

#ifndef UINT64
#define UINT64 unsigned long long
#endif

#else

#ifndef INLINE
#define INLINE __inline
#endif

#ifndef UINT64
#define UINT64 __int64
#endif

#endif

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <iconv.h>

#define HASHTABLESIZE (64*1024)
#define BWSHIFTABLESIZE (64*1024)
#define MTH_MWM 0
#define MTH_BM  1
#define HASHBYTES16    2

typedef struct
{
    unsigned char *P;
    int            M;
    short          bcShift[256];
}HBM_STRUCT;


/*
**  This struct is used internally my mwm.c 
*/

typedef struct _mwm_pattern_struct
{
    struct _mwm_pattern_struct * next;
    unsigned char              *psPat;             // selected pattern, used by hash tables
    unsigned char              *psUpperPat;   // pattern array, no case
    unsigned char              *psPatCase;    // pattern array, case(exact)
    unsigned                   psLen;   // length of pattern in bytes
    int                        psID;    //  OTNX
    unsigned                   psID2;    // PatMatchData
    int                        psIID;    //internal ID, used by the pattern matcher
    int 		               psGID;	  // Group ID
    unsigned                   psNoCase;// Pattern match is case insensitive if true
    int                        psOffset;  // start search this deep
    unsigned                   psDepth;   // number of bytes after offset to search
    HBM_STRUCT                 * psBmh;
}MWM_PATTERN_STRUCT;


#define HASH_TYPE short
typedef struct _mwm_struct
{
    int msMethod;  /* MTH_BM, MTH_MWM */
    MWM_PATTERN_STRUCT * plist;
	
    /*  Array of Patterns */
    int                 msMaxPatterns;
    MWM_PATTERN_STRUCT *msPatArray;
	
    /* Array of Group Counts, # of patterns in each hash group */
    unsigned short *msNumArray;
    /* One byte patterns */
    unsigned short  msNumArray1[256];
    /* Number of Patterns loaded */
    int        msNumPatterns;

	
    /* Wu-Manber Hash Tables */
    unsigned   msNumHashEntries;
    HASH_TYPE *msHash;           // 2+ character Pattern Big Hash Table
    HASH_TYPE  msHash1[256];     // One character Pattern Hash Table

    /* Bad Character Shift Table */
    short    msShift[256];
    unsigned msShiftLen;
    /* Bad Word Shift Table */
    unsigned char* msShift2;
    int msLargeShifts;
    /* Good B Suffix Shift Table */
    unsigned short msGBSShift[256];
    unsigned char *msGBSShift2;

    /* Case insensitive search */
    int     msNoCase;
	
    /* search function */
    int (*search)( struct _mwm_struct * ps,
                   unsigned char* Tx, int n, unsigned char* Tc,
                   int(*match)(int id, int groupid, int index, void * data ),
                   void * data );
	
    /* Print Group Details */
    int msDetails;
    /* Pattern Group Stats  */
    int   msSmallest;
    int   msLargest;
    int   msAvg;
    int   msTotal;
    int * msLengths;
    int 	firststop;
    float   	msGBSrate;
    int 	msGroupNum;
}MWM_STRUCT;


#define MAX_SEARCH_GROUP_KEYWORD_NUM 32
#define MAX_SEARCH_GROUP_NUM  		32

#define MWM_MAX_KEYWORD_NUM 		1024
#define MWM_MAX_GROUP_NUM 		32

#define MWM_MAX_KEYWORD_NUM2 	16
#define MWM_MAX_GROUP_NUM2 		1024

typedef unsigned char * SEARCH_RESULT_SINGLE;
typedef unsigned short int * OFFSET_SINGLE;

typedef unsigned char SEARCH_RESULT_GROUP[MWM_MAX_GROUP_NUM];
typedef unsigned char SEARCH_RESULT_KEYWORD[MWM_MAX_GROUP_NUM][MWM_MAX_KEYWORD_NUM];
typedef unsigned short int OFFSET_GROUP[MWM_MAX_GROUP_NUM][MWM_MAX_KEYWORD_NUM];

typedef unsigned char SEARCH_RESULT_GROUP2[MWM_MAX_GROUP_NUM2];
typedef unsigned char SEARCH_RESULT_KEYWORD2[MWM_MAX_GROUP_NUM2][MWM_MAX_KEYWORD_NUM2];
typedef unsigned short int OFFSET_GROUP2[MWM_MAX_GROUP_NUM2][MWM_MAX_KEYWORD_NUM2];

#define MWM_NOVALID_GROUP  0XFFFFFFFF

typedef struct
{
    unsigned char * search_result_keyword;
    unsigned int search_result_group;
}SEARCH_SEARCH;

typedef struct
{
    unsigned char* search_result;
    unsigned short int * offset;
}SINGLE_MATCH_RESULT;

typedef struct
{
    unsigned char* search_result_group;
    unsigned char (* search_result_keyword)[MWM_MAX_KEYWORD_NUM];
    unsigned short int (* offset)[MWM_MAX_KEYWORD_NUM];
}GROUP_MATCH_RESULT;

typedef struct
{
    unsigned char* search_result_group;
    unsigned char (* search_result_keyword)[MWM_MAX_KEYWORD_NUM2];
    unsigned short int (* offset)[MWM_MAX_KEYWORD_NUM2];
}GROUP_MATCH_RESULT2;

typedef struct
{
    int * search_result_group;
    int firststop;
    int matched_group_num;
}GROUP_RESULT_USERDEF;


// old pattern input struct
typedef struct
{
    int keyword_id;
    char keyword[128];
    int keyword_length;
}SearchGroupKeywordStru;

typedef struct
{
    int    group_id;
    int    group_keyword_num;
    SearchGroupKeywordStru group_keyword[MWM_MAX_KEYWORD_NUM];
}SearchGroupStru;

typedef struct
{
    signed char search_version[64];
    int        search_group_num;
    SearchGroupStru search_group[MWM_MAX_GROUP_NUM];
}SearchStru;

// new pattern input struct with no id info
typedef struct
{
    signed char keyword[128];
    int keyword_length;
}SearchKeywordStruNoid;

typedef struct
{
    int group_keyword_num;
    SearchKeywordStruNoid group_keyword[MWM_MAX_KEYWORD_NUM2];
}SearchGroupStruNoid;

typedef struct
{
    int search_group_num;
    SearchGroupStruNoid search_group[MWM_MAX_GROUP_NUM2];
}SearchStruNoid;


// struct for unlimited pattern_num group search
typedef struct _search_keyword_stru_userdef
{
    signed char * keyword;
    int keyword_length;
    int nocase;
    //int id;
    struct _search_keyword_stru_userdef * next;
}SearchKeywordStruUser;

typedef struct
{
    int group_id;
    int group_keyword_num;
    SearchKeywordStruUser * group_keyword;
}SearchGroupStruUser;

typedef struct
{
    int search_group_num;
    SearchGroupStruUser * search_group;
}SearchStruUser;


typedef MWM_STRUCT*  BEAP_MWM_SEARCH_HANDLE;


// old interface
BEAP_MWM_SEARCH_HANDLE beap_mwm_search_init(SearchStru *searchconf, int nocase);
unsigned long beap_mwm_search_search(BEAP_MWM_SEARCH_HANDLE beap_mwm_search_handle,
                           unsigned char* search_result,
                           signed char *buf,
                           int length);
int beap_mwm_search_free(BEAP_MWM_SEARCH_HANDLE);


// single group interface
BEAP_MWM_SEARCH_HANDLE beap_mwm_search_init_single(SearchKeywordStruNoid * keyword_stru, int keyword_stru_num, int nocase);
int beap_mwm_search_single(BEAP_MWM_SEARCH_HANDLE beap_mwm_search_handle,
                           SEARCH_RESULT_SINGLE search_result,
			   int search_result_num,
                           OFFSET_SINGLE offset,
			   int offset_num,
                           signed char * buf,
                           int length,
                           int firststop);


// multi group interface
BEAP_MWM_SEARCH_HANDLE beap_mwm_search_init_group(SearchStru *searchconf, int nocase);
int beap_mwm_search_group(BEAP_MWM_SEARCH_HANDLE beap_mwm_search_handle,
                          SEARCH_RESULT_GROUP search_result_group,
                          SEARCH_RESULT_KEYWORD search_result_keyword,
                          OFFSET_GROUP offset,
                          signed char *buf,
                          int length,
                          int firststop);

BEAP_MWM_SEARCH_HANDLE beap_mwm_search_init_group2(SearchStruNoid *searchconf, int nocase);
int beap_mwm_search_group2(BEAP_MWM_SEARCH_HANDLE beap_mwm_search_handle,
                          SEARCH_RESULT_GROUP2 search_result_group,
                          SEARCH_RESULT_KEYWORD2 search_result_keyword,
                          OFFSET_GROUP2 offset,
                          signed char *buf,
                          int length,
                          int firststop);


// multi group interface user define num
BEAP_MWM_SEARCH_HANDLE beap_mwm_search_init_userdef(SearchStruUser * searchconf);
int beap_mwm_search_group_userdef(BEAP_MWM_SEARCH_HANDLE beap_mwm_search_handle, 
				  int * search_result_group, 
				  int search_result_group_num,
				  signed char *buf,
				  int length, 
				  int firststop);


// function declaration
MWM_STRUCT* mwmNew(void);
void mwmFree(void * pv);
int mwmAddPatternEx(void *pv, unsigned char * P, int m, 
		    unsigned noCase, unsigned offset, unsigned depth, int id, int iid ,int gid);
int mwmPrepPatterns(void * pv);
int mwmSearch( void * pv,
		    unsigned char * T, int n,
		    int(*match)(int, int , int, void * ),
		    void * data);

char iconv_utf8_gbk(char *to, int to_len, char *from, int from_len);
char iconv_utf8_Big5(char *to, int to_len, char *from, int from_len);
#endif

