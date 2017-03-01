
#include<string.h>
#include "mwm.h"
#include "data_def.h"

static unsigned char xlatcase[256];

static void init_xlatcase(void)
{
    int i;
    for (i=0; i<256; i++)
    {
        xlatcase[ i ] =  toupper(i);
    }
}


MWM_STRUCT* mwmNew(void)
{
    MWM_STRUCT * p = (MWM_STRUCT *)calloc(sizeof(MWM_STRUCT), 1);
    if (!p)
    {
        return 0;
    }

    init_xlatcase();
    p->msSmallest = 32000;

    return p;
}


void mwmFree(void * pv)
{
    MWM_STRUCT * p = (MWM_STRUCT *)pv;
    MWM_PATTERN_STRUCT *pattern = NULL;
    int  kk=0;
    if (p)
    {
        if (p->msNumArray)  free(p->msNumArray);
        if (p->msHash)  free(p->msHash);
        if (p->msShift2) free(p->msShift2);
        if (p->msGBSShift2) free(p->msGBSShift2);
        if (p->msLengths) free(p->msLengths);

        if (p->msMethod == MTH_BM)
        {
            int i;

            /* Allocate and initialize the BMH data for each pattern */
            for (i=0; i<p->msNumPatterns; i++)
            {

#ifdef COPYPATTERN
                if (((p->msPatArray[i].psBmh)->P) != NULL)
                    free((p->msPatArray[i].psBmh)->P);
#endif
                if ((p->msPatArray[i].psBmh) != NULL)
                    free(p->msPatArray[i].psBmh);
            }
        }


        if (p->msPatArray) free( p->msPatArray );

        while (p->plist != NULL && kk < p->msNumPatterns)
        {
            if ((p->plist)->next != NULL)
                pattern = (p->plist)->next;
            else
                pattern = NULL;

            if (p->plist->psUpperPat != NULL)  free(p->plist->psUpperPat);
            if (p->plist->psPatCase != NULL)  free(p->plist->psPatCase);
            if (p->plist->psBmh != NULL)  free(p->plist->psBmh);
            free(p->plist);

            if (pattern != NULL)
                p->plist = pattern;

            kk++;
        }
        free(p);
    }
}


/*
static int match(int id, int groupid, int index, void * data)
{
	printf("^^^^^^^^^^^^^^^^^^^^^^^^\n");
    SEARCH_SEARCH *ps = (SEARCH_SEARCH*)data;
    ps->search_result_group |= (1<<(unsigned int)groupid);

    if ( ps->search_result_keyword != NULL)
    {
        ps->search_result_keyword[groupid] |= (1<<id);
    }

    return 0;
}
*/

static int match(int rule_id, int key_id, int index, void * data)
{
    SEARCH_SEARCH *ps = (SEARCH_SEARCH*)data;
    ps->search_result_group |= (1<<(unsigned int)rule_id);

	//printf("@@@@@@@@@@@@@@@ bingo, addr of rslt: %p, rule_id: %d, key_id: %d\n", ps->search_result_keyword, rule_id, key_id);

    if ( ps->search_result_keyword != NULL)
    {
        //ps->search_result_keyword[groupid] |= (1<<id);
		//unsigned char *rule_rslt_begin = ps->search_result_keyword + rule_id * (MAX_KEY_NUM_PER_RULE/8);
		//printf("rule_rslt_begin = %p\n", rule_rslt_begin);
		
		//unsigned char *key_rslt_begin = rule_rslt_begin + (key_id / 8);
		//printf("key_rslt_begin = %p\n", key_rslt_begin);
		//printf("(key_id % 8) = %d\n", key_id % 8);
		//printf("sizeof(unsigned char) = %d\n", sizeof(unsigned char));
		//unsigned char x = (unsigned char)(((unsigned )0x1) << (key_id % 8));
		//printf("x = %d\n", (int)x);
		//(*key_rslt_begin) |= (unsigned char)x;
		ps->search_result_keyword[rule_id] = 1;
    }

    return 0;
}


static int match_single(int id, int groupid, int index, void *data)
{
    SINGLE_MATCH_RESULT* ps = (SINGLE_MATCH_RESULT*)data;

    if (ps->search_result != NULL)
    {
        ps->search_result[id]++;
    }

    if (ps->offset != NULL)
    {
        if(ps->offset[id]==0)
            ps->offset[id] = index;
    }
    return 0;
}


static int match_group(int id, int groupid, int index, void *data)
{
    GROUP_MATCH_RESULT* ps = (GROUP_MATCH_RESULT*)data;

    if (ps->search_result_group != NULL)
    {
        ps->search_result_group[groupid]++;
    }

    if (ps->search_result_keyword != NULL)
    {
        ps->search_result_keyword[groupid][id]++;
    }

    if (ps->offset != NULL)
    {
        if(ps->offset[groupid][id] == 0)
            ps->offset[groupid][id] = index;
    }

    return 0;
}


static int match_group2(int id, int groupid, int index, void *data)
{
    GROUP_MATCH_RESULT2* ps = (GROUP_MATCH_RESULT2*)data;

    if (ps->search_result_group != NULL)
    {
        ps->search_result_group[groupid]++;
    }

    if (ps->search_result_keyword != NULL)
    {
        ps->search_result_keyword[groupid][id]++;
    }

    if (ps->offset != NULL)
    {
        if(ps->offset[groupid][id] == 0)
            ps->offset[groupid][id] = index;
    }

    return 0;
}


static int match_group_userdef(int id, int groupid, int index, void *data)
{
    GROUP_RESULT_USERDEF *ps = (GROUP_RESULT_USERDEF*)data;

    if (ps->search_result_group != NULL)
    {
        if (ps->firststop)
        {
            ps->search_result_group[0] = groupid;
            ps->matched_group_num ++;
        }
        else
        {
            if (ps->search_result_group[id] == MWM_NOVALID_GROUP)
            {
                ps->matched_group_num ++;
                ps->search_result_group[id] = groupid;
            }
        }
    }

    return 0;
}


static  void ConvCaseToUpper(unsigned char *s, int m)
{
    int  i;
    for (i=0; i < m; i++)
    {
        s[i] = xlatcase[ s[i] ];
    }
}


static void ConvCaseToUpperEx(unsigned char * d, unsigned char *s, int m)
{
    int i;
    for (i=0; i < m; i++)
    {
        d[i] = xlatcase[ s[i] ];
    }
}


int mwmAddPatternEx(void *pv, unsigned char * P, int m,
                    unsigned noCase, unsigned offset, unsigned depth, int id, int iid ,int gid)
{
    MWM_STRUCT *ps = (MWM_STRUCT*)pv;
    MWM_PATTERN_STRUCT *plist=0;

    MWM_PATTERN_STRUCT *p = (MWM_PATTERN_STRUCT*)calloc(sizeof(MWM_PATTERN_STRUCT), 1);

    if (!p) return -1;

#ifdef REQUIRE_UNIQUE_PATTERNS
	printf("mwmAddPatternEx: macro REQUIRE_UNIQUE_PATTERNS defined, check repeated keywords\n"); // debuged by zhangjl
    for (plist=ps->plist; plist!=NULL; plist=plist->next )
    {
        if (plist->psLen == m)
        {
            if (memcmp(P, plist->psUpperPat, m) == 0)
            {
                return 0;  /*already added */
            }
        }
    }
#endif

    if (ps->plist)
    {
        for (plist=ps->plist; plist->next!=NULL; plist=plist->next)
            ;
        plist->next = p;
    }
    else
        ps->plist = p;


    /* Allocate and store the Pattern  'P' with NO CASE info*/
    p->psUpperPat =  (unsigned char*)malloc(m);
    if (!p->psUpperPat) return -1;

    memcpy(p->psUpperPat, P, m);

    ConvCaseToUpper(p->psUpperPat, m);

    /* Allocate and store the Pattern  'P' with CASE info*/
    p->psPatCase =  (unsigned char*)malloc(m);
    if (!p->psPatCase) return -1;

    memcpy(p->psPatCase, P, m);

    p->psLen    = m;
    p->psID     = id;
    p->psIID    = iid;
    p->psGID    = gid;
    p->psNoCase = noCase;
    p->psOffset = offset;
    p->psDepth  = depth;

    ps->msNoCase += noCase;

    ps->msNumPatterns++;

    if (p->psLen < (unsigned)ps->msSmallest) ps->msSmallest= p->psLen;
    if (p->psLen > (unsigned)ps->msLargest) ps->msLargest = p->psLen;

    ps->msTotal   += p->psLen;
    ps->msAvg      = ps->msTotal / ps->msNumPatterns;

    return 1;
}


static void mwmAnalyzePattens(MWM_STRUCT * ps)
{
    int i;

    ps->msLengths= (int*) malloc(sizeof(int) * (ps->msLargest+1));

    if (ps->msLengths)
    {
        memset( ps->msLengths, 0, sizeof(int) * (ps->msLargest+1));

        for (i=0; i<ps->msNumPatterns; i++)
        {
            ps->msLengths[ps->msPatArray[i].psLen]++;
        }
    }
}


static unsigned HASH16(unsigned char * T)
{
    return (unsigned short) (((*T)<<8) | *(T+1));
}


int FatalError( signed char * s , ... )
{
    printf("FatalError: %s\n",s);
    exit(0);
}


/*
*	Calculate B's value
*/
static signed char mwmCalB(MWM_STRUCT * ps)
{
    int m = ps->msShiftLen;

    if ( m > 2 && ps->msNumPatterns * m > 128 )
    {
        ps->msLargeShifts = 1;
        return 1;
    }
    return 0;
}


/*
*  Standard Bad Character Multi-Pattern Skip Table
*/
static void mwmPrepBadCharTable(MWM_STRUCT * ps)
{
    unsigned  short i, k,  m, cindex, shift, mindex;

    int arr[ps->msNumPatterns];
    int p=0,s=0;

    m = ps->msShiftLen;

    /* Initialze the default shift table. Max shift of 256 characters */
    for (i=0; i<256; i++)
    {
        ps->msShift[i] = m;
    }

    /*  Multi-Pattern BAD CHARACTER SHIFT */
    for(i=0;i<ps->msNumPatterns;i++)
    {
        for(k=0;k<m-1;k++)
        {
            shift = (unsigned short)(m - 1 - k);
            if( shift > 255 ) shift = 255;

            cindex = ps->msPatArray[ i ].psPat[ k ];

            if( shift < ps->msShift[ cindex ] )
                ps->msShift[ cindex ] = shift;
        }
    }
    for(i=0;i<ps->msNumPatterns;i++)
    {
        mindex = ps->msPatArray[i].psPat[m-1];
        if(ps->msShift[mindex] != 0)
        {
            ps->msGBSShift[mindex] = ps->msShift[mindex];
            arr[p] = mindex;
            p++;
        }
        ps->msShift[mindex] = 0;
    }
    for ( i=0; i<p; i++ )
    {
        if ( ps->msGBSShift[arr[i]] == 1)
            s++;
    }
    ps->msGBSrate = 100*(float)s/(float)p;
}


/*
** Prep and Build a Bad Word Shift table
*/
static void mbmPrepBadWordTable(MWM_STRUCT * ps)
{
    int i;
    unsigned short j;
    unsigned  short  k,  m, cindex, mindex;
    unsigned  shift;

    ps->msShift2 = (unsigned char *)malloc(BWSHIFTABLESIZE*sizeof(signed char));
    ps->msGBSShift2 = (unsigned char *)malloc(BWSHIFTABLESIZE*sizeof(signed char));
    if (!ps->msShift2)
        return;

    m = ps->msShiftLen;

    /* Initialze the default shift table. */
    /* Update accurate bad word shift table. */

    for(i=0;i<BWSHIFTABLESIZE;i++)
    {
        ps->msShift2[i] = (unsigned char)(m);
        ps->msGBSShift2[i] = (unsigned char)(m);
    }

    /* Multi-Pattern Bad Word Shift Table Values */

    /* additional step */
    shift = m - 1;
    for(i=0;i<ps->msNumPatterns;i++)
    {
        for(j=0;j<256;j++)
        {
            cindex = ( j | (ps->msPatArray[i].psPat[0]<<8));
            if( shift < ps->msShift2[cindex])
                ps->msShift2[cindex] = shift;
        }
    }
    /* additional end */

    for(i=0;i<ps->msNumPatterns;i++)
    {
        for(k=0;k<m-2;k++)
        {
            shift = (unsigned short)(m - 2 - k);
            if( shift > 255 ) shift = 255;

            cindex = ( ps->msPatArray[i].psPat[ k ] | (ps->msPatArray[i].psPat[k+1]<<8) );

            if( shift < ps->msShift2[ cindex ] )
                ps->msShift2[ cindex ] = shift;
        }
    }
    for(i=0;i<ps->msNumPatterns;i++)
    {
        mindex = (ps->msPatArray[i].psPat[m-2] | (ps->msPatArray[i].psPat[m-1]<<8));
        if(ps->msShift2[mindex] != 0)
            ps->msGBSShift2[mindex] = ps->msShift2[mindex];
        ps->msShift2[mindex] = 0;
    }
}


HBM_STRUCT * hbm_prepx(HBM_STRUCT *p, unsigned char * pat, int m)
{
    int     k;

    if( !m ) return 0;
    if( !p ) return 0;

#ifdef COPYPATTERN
    p->P = (unsigned char*)malloc( (m + 1)*sizeof(signed char) );
    if (!p->P) return 0;
    memcpy(p->P, pat, m);
#else
    p->P = pat;
#endif

    p->M = m;

    /* Compute normal Boyer-Moore Bad Character Shift */
    for (k = 0; k < 256; k++) p->bcShift[k] = m;
    for (k = 0; k < m; k++)   p->bcShift[pat[k]] = m - k - 1;

    return p;
}


/*
*
*/
HBM_STRUCT * hbm_prep(unsigned char * pat, int m)
{
    HBM_STRUCT    *p;

    p = (HBM_STRUCT*)malloc(sizeof(HBM_STRUCT));
    if (!p) return 0;

    return hbm_prepx(p, pat, m);
}


/*
*   Boyer-Moore Horspool
*   Does NOT use Sentinel Byte(s)
*   Scan and Match Loops are unrolled and separated
*   Optimized for 1 byte patterns as well
*/
static  unsigned char * hbm_match(HBM_STRUCT * px, unsigned char * text, int n)
{
    unsigned char *pat, *t, *et, *q;
    int            m1, k;
    short    *bcShift;

    //printf("0x%d",px);

    m1     = px->M - 1;
    pat    = px->P;
    bcShift= px->bcShift;

    t  = text + m1;
    et = text + n;

    /* Handle 1 Byte patterns - it's a faster loop */
    if (!m1)
    {
        for( ;t<et; t++ )
            if( *t == *pat ) return t;
        return 0;
    }

    /* Handle MultiByte Patterns */
    while (t < et)
    {
        /* Scan Loop - Bad Character Shift */
        do
        {
            t += bcShift[*t];
            if( t >= et )return 0;;

            t += (k=bcShift[*t]);
            if( t >= et )return 0;

        }
        while( k );

        /* Unrolled Match Loop */
        k = m1;
        q = t - m1;
        while (k >= 4)
        {
            if ( pat[k] != q[k] )goto NoMatch;  k--;
            if ( pat[k] != q[k] )goto NoMatch;  k--;
            if ( pat[k] != q[k] )goto NoMatch;  k--;
            if ( pat[k] != q[k] )goto NoMatch;  k--;
        }
        /* Finish Match Loop */
        while ( k >= 0 )
        {
            if ( pat[k] != q[k] )goto NoMatch;  k--;
        }
        /* If matched - return 1st char of pattern in text */
        return q;

    NoMatch:

        /* Shift by 1, this replaces the good suffix shift */
        t++;
    }
    return 0;
}


/*
** bcompare::
**
** Perform a Binary comparsion of 2 byte sequences of possibly
** differing lengths.
**
** returns -1 a < b
**         +1 a > b
**          0 a = b
*/
static int bcompare( unsigned char *a, int alen, unsigned char * b, int blen )
{
    int stat;
    if ( alen == blen )
    {
        return memcmp(a,b,alen);
    }
    else if ( alen < blen )
    {
        if ( (stat=memcmp(a,b,alen)) != 0 )
            return stat;
        return -1;
    }
    else
    {
        if ( (stat=memcmp(a,b,blen)) != 0 )
            return stat;
        return +1;
    }
}


static int sortcmp( const void * e1, const void * e2 )
{
    MWM_PATTERN_STRUCT *r1= (MWM_PATTERN_STRUCT*)e1;
    MWM_PATTERN_STRUCT *r2= (MWM_PATTERN_STRUCT*)e2;
    return bcompare( r1->psPat, r1->psLen, r2->psPat, r2->psLen );
}


static void mwmPrepHashedPatternGroups(MWM_STRUCT * ps)
{
    unsigned sindex,hindex,ningroup;
    int i;

    /*
    **  Allocate and Init 2+ byte pattern hash table
    */
    ps->msNumHashEntries = HASHTABLESIZE;
    ps->msHash = (HASH_TYPE*)malloc( sizeof(HASH_TYPE) * ps->msNumHashEntries );
    if ( !ps->msHash )
    {
        FatalError((signed char*)"No memory in mwmPrephashedPatternGroups()\n");
    }

    /* Init Hash table to default value */
    for (i=0; i<(int)ps->msNumHashEntries; i++)
    {
        ps->msHash[i] = (HASH_TYPE)-1;
    }

    /* Initialize The One Byte Pattern Hash Table */
    for (i=0; i<256; i++)
    {
        ps->msHash1[i] = (HASH_TYPE)-1;
    }

    /*
    ** Add the patterns to the hash table
    */
    for (i=0; i<ps->msNumPatterns; i++)
    {
        if ( ps->msPatArray[i].psLen > 1 )
        {
            hindex = HASH16(ps->msPatArray[i].psPat);
            sindex = ps->msHash[ hindex ] = i;
            ningroup = 1;
            while ( (++i < ps->msNumPatterns) && (hindex==HASH16(ps->msPatArray[i].psPat)) )
                ningroup++;
            ps->msNumArray[ sindex ] = ningroup;
            i--;
        }
        else if ( ps->msPatArray[i].psLen == 1 )
        {
            hindex = ps->msPatArray[i].psPat[0];
            sindex = ps->msHash1[ hindex ] = i;
            ningroup = 1;

            while ((++i < ps->msNumPatterns) && (hindex == ps->msPatArray[i].psPat[0]) && (ps->msPatArray[i].psLen == 1))
                ningroup++;

            ps->msNumArray[ sindex ] = ningroup;
            i--;
        }
    }
}


static int mwmGroupMatch2( MWM_STRUCT * ps,
                           int index,
                           unsigned char * Tx,
                           unsigned char * T,
                           unsigned char * Tc,
                           int Tleft,
                           void * data,
                           int (*match)(int, int , int, void*)
                         )
{
    int k, nfound=0;
    MWM_PATTERN_STRUCT * patrn;
    MWM_PATTERN_STRUCT * patrnEnd;


    /* Process the Hash Group Patterns against the current Text Suffix */
    patrn    = &ps->msPatArray[index];
    patrnEnd = patrn + ps->msNumArray[index];

    /*  Match Loop - Test each pattern in the group against the Text */
    for ( ;patrn < patrnEnd; patrn++ )
    {
        unsigned char *p, *q;

        /* Test if this Pattern is to big for Text, not a possible match */
        if ( (unsigned)Tleft < patrn->psLen )
            continue;


        /* Setup the reverse string compare */
        k = patrn->psLen - HASHBYTES16 - 1;
        q = patrn->psPat + HASHBYTES16;
        p = T            + HASHBYTES16;

        /* Compare strings backward, unrolling does not help in perf tests. */
        while ( k >= 0 && (q[k] == p[k]) ) k--;

        /* We have a content match - call the match routine for further processing */
        if ( k < 0 )
        {
            if ( Tc && ps->msNoCase && !patrn->psNoCase)
            {
                /* Validate a case sensitive match - than call match */
                if (memcmp(patrn->psPatCase, &Tc[T-Tx], patrn->psLen) )
                {
                    continue;
                }
            }

            nfound++;
            int stop = match(patrn->psID, patrn->psGID, (int)(T-Tx), data);
            if (stop  || ps->firststop)
            {
                return -(nfound+1);
            }
        }
    }
    return nfound;
}


/*
**
**  No Bad Character Shifts
**  Handles pattern groups with one byte or larger patterns
**  Uses 1 byte and 2 byte hash tables to group patterns
**
*/
static int mwmSearchExNoBC( MWM_STRUCT *ps,
                            unsigned char * Tx, int n, unsigned char * Tc,
                            int(*match)(int, int, int, void* ),
                            void * data
                          )
{
    int                 Tleft, index, nfound, ng;
    unsigned char      *T, *Tend, *B;
    MWM_PATTERN_STRUCT *patrn, *patrnEnd;

    nfound = 0;

    Tleft = n;
    Tend  = Tx + n;

    /* Test if text is shorter than the shortest pattern */
    if ( (unsigned)n < ps->msShiftLen )
    {
        return 0;
    }

    /*  Process each suffix of the Text, left to right, incrementing T so T = S[j] */
    for (T = Tx, B = Tx + ps->msShiftLen - 1; B < Tend; T++, B++, Tleft--)
    {
        /* Test for single char pattern matches */
        if ( (index = ps->msHash1[*T]) != (HASH_TYPE)-1 )
        {
            patrn    = &ps->msPatArray[index];
            patrnEnd = patrn + ps->msNumArray[index];

            for ( ;patrn < patrnEnd; patrn++ )
            {
                if ( Tc && ps->msNoCase  && !patrn->psNoCase )
                {
                    if ( patrn->psPatCase[0] != Tc[T-Tx] )
                    {
                        continue;
                    }
                }

                nfound++;
                int stop = match(patrn->psID, patrn->psGID, (int)(T-Tx), data);
                if (stop || ps->firststop)
                {
                    return nfound;
                }
            }
        }

        /*
        ** Test for last char in Text, one byte pattern test
        ** was done above, were done.
        */
        if ( Tleft == 1 )
        {
            return nfound;
        }

        /*
        ** Test if the 2 char prefix of this suffix shows up
        ** in the hash table
        */
        if  ((index = ps->msHash [ ( (*T)<<8 ) | *(T+1) ] ) == (HASH_TYPE)-1 )
            continue;

        /* Match this group against the current suffix */
        ng = mwmGroupMatch2( ps, index,Tx, T, Tc, Tleft, data, match );
        if ( ng < 0 )
        {
            ng = -ng;
            ng--;
            nfound += ng;

            return nfound;
        }
        else
        {
            nfound += ng;
        }
    }
    return nfound;
}


/*
**
**  Uses Bad Character Shifts
**  Handles pattern groups with 2 or more bytes per pattern
**  Uses 2 byte hash table to group patterns
**
*/
static int mwmSearchExBC( MWM_STRUCT *ps,
                          unsigned char * Tx, int n, unsigned char * Tc,
                          int(*match)(int, int, int, void * ),
                          void * data
                        )
{
    int                 Tleft, index, nfound, tshift, ng, bshift = 1;
    unsigned char      *T, *Tend, *B;
    /*MWM_PATTERN_STRUCT *patrn, *patrnEnd;*/

    nfound = 0;

    Tleft = n;
    Tend  = Tx + n;

    /* Test if text is shorter than the shortest pattern */
    if( (unsigned)n < ps->msShiftLen )
        return 0;


    /*  Process each suffix of the Text, left to right, incrementing T so T = S[j] */
    for ( T = Tx, B = Tx + ps->msShiftLen - 1; B < Tend; T+=bshift, B+=bshift, Tleft-=bshift )
    {
        /* Multi-Pattern Bad Character Shift */
        while ( (tshift=ps->msShift[*B]) > 0 )
        {
            B += tshift; T += tshift; Tleft -= tshift;
            if ( B >= Tend ) return nfound;

            tshift=ps->msShift[*B];
            B += tshift; T += tshift; Tleft -= tshift;
            if ( B >= Tend ) return nfound;
        }

        /* Test for last char in Text, one byte pattern test was done above, were done. */
        if ( Tleft == 1 )
            return nfound;

        bshift = ps->msGBSShift[*B];

        /* Test if the 2 char prefix of this suffix shows up in the hash table */
        if ( (index = ps->msHash [ ( (*T)<<8 ) | *(T+1) ] ) == (HASH_TYPE)-1 )
            continue;

        /* Match this group against the current suffix */
        ng = mwmGroupMatch2( ps, index,Tx, T, Tc, Tleft, data, match );
        if( ng < 0 )
        {
            ng = -ng;
            ng--;
            nfound += ng;
            return nfound;
        }
        else
        {
            nfound += ng;
        }
    }
    return nfound;
}


/* GBSShift no use */
static int mwmSearchExBCNoGBS( MWM_STRUCT *ps,
                               unsigned char * Tx, int n, unsigned char * Tc,
                               int(*match)(int, int, int, void * ),
                               void * data
                             )
{
    int                 Tleft, index, nfound, tshift, ng;
    unsigned char      *T, *Tend, *B;
    /*MWM_PATTERN_STRUCT *patrn, *patrnEnd;*/

    nfound = 0;

    Tleft = n;
    Tend  = Tx + n;

    /* Test if text is shorter than the shortest pattern */
    if( (unsigned)n < ps->msShiftLen )
        return 0;


    /*  Process each suffix of the Text, left to right, incrementing T so T = S[j] */
    for ( T = Tx, B = Tx + ps->msShiftLen - 1; B < Tend; T++, B++, Tleft-- )
    {
        /* Multi-Pattern Bad Character Shift */
        while ( (tshift=ps->msShift[*B]) > 0 )
        {
            B += tshift; T += tshift; Tleft -= tshift;
            if ( B >= Tend ) return nfound;

            tshift=ps->msShift[*B];
            B += tshift; T += tshift; Tleft -= tshift;
            if ( B >= Tend ) return nfound;
        }

        /* Test for last char in Text, one byte pattern test was done above, were done. */
        if ( Tleft == 1 )
            return nfound;

        /* Test if the 2 char prefix of this suffix shows up in the hash table */
        if ( (index = ps->msHash [ ( (*T)<<8 ) | *(T+1) ] ) == (HASH_TYPE)-1 )
            continue;

        /* Match this group against the current suffix */
        ng = mwmGroupMatch2( ps, index,Tx, T, Tc, Tleft, data, match );
        if( ng < 0 )
        {
            ng = -ng;
            ng--;
            nfound += ng;
            return nfound;
        }
        else
        {
            nfound += ng;
        }
    }
    return nfound;
}


/*
**
**  Uses Bad Word Shifts
**  Handles pattern groups with 2 or more bytes per pattern
**  Uses 2 byte hash table to group patterns
**
*/
static int mwmSearchExBW( MWM_STRUCT *ps,
                          unsigned char * Tx, int n, unsigned char * Tc,
                          int(*match) (int, int, int,void * ),
                          void * data
                        )
{
    int                 Tleft, index, nfound, tshift, ng, bshift;
    unsigned char      *T, *Tend, *B;
    int 		btrans = 0;

    nfound = 0;

    Tleft = n;
    Tend  = Tx + n;

    /* Test if text is shorter than the shortest pattern */
    if ( (unsigned)n < ps->msShiftLen )
        return 0;

    /*  Process each suffix of the Text, left to right, incrementing T so T = S[j] */
    for ( T = Tx, B = Tx + ps->msShiftLen - 1; B < Tend; T+=bshift, B+=bshift, Tleft-=bshift )
    {
        /* Multi-Pattern Bad Word Shift */
        btrans = ((*B)<<8) | *(B-1);
        tshift = ps->msShift2[btrans];
        while ( tshift )
        {
            B     += tshift;  T += tshift; Tleft -= tshift;
            if( B >= Tend ) return nfound;
            btrans = ((*B)<<8) | *(B-1);
            tshift = ps->msShift2[btrans];
        }

        /* Test for last char in Text, we are done, one byte pattern test was done above. */
        if ( Tleft == 1 ) return nfound;

        bshift = ps->msGBSShift2[btrans];

        /* Test if the 2 char prefix of this suffix shows up in the hash table */
        if( (index = ps->msHash [ ( (*T)<<8 ) | *(T+1) ] ) == (HASH_TYPE)-1 )
            continue;


        /* Match this group against the current suffix */
        ng = mwmGroupMatch2( ps, index,Tx, T, Tc, Tleft, data, match );
        if( ng < 0 )
        {
            ng = -ng;
            ng--;
            nfound += ng;
            return nfound;
        }
        else
        {
            nfound += ng;
        }
    }
    return nfound;
}


/*
**
** mwmPrepPatterns::    Prepare the pattern group for searching
**
*/
int mwmPrepPatterns( void * pv )
{
    MWM_STRUCT * ps = (MWM_STRUCT *) pv;
    int kk;
    MWM_PATTERN_STRUCT * plist;
    unsigned  small_value=32000, large_value=0;
    int i,m;

    /* Build an array of pointers to the list of Pattern nodes */
    ps->msPatArray = (MWM_PATTERN_STRUCT*)calloc( sizeof(MWM_PATTERN_STRUCT), ps->msNumPatterns );
    if ( !ps->msPatArray )
    {
        return -1;
    }
    ps->msNumArray = (unsigned short *)calloc( sizeof(short), ps->msNumPatterns  );
    if ( !ps->msNumArray )
    {
        return -1;
    }

    /* select pattern base on Case sensitive */
    for ( kk=0, plist = ps->plist; plist!=NULL && kk < ps->msNumPatterns; plist=plist->next )
    {

        plist->psPat = ps->msNoCase ? plist->psUpperPat : plist->psPatCase;
    }



    /* Copy the list node info into the Array */
    for ( kk=0, plist = ps->plist; plist!=NULL && kk < ps->msNumPatterns; plist=plist->next )
    {
        memcpy( &ps->msPatArray[kk++], plist, sizeof(MWM_PATTERN_STRUCT) );
    }

    mwmAnalyzePattens( ps );

    /* Sort the patterns */
    qsort( ps->msPatArray, ps->msNumPatterns, sizeof(MWM_PATTERN_STRUCT), sortcmp );

    /* Build the Hash table, and pattern groups, per Wu & Manber */
    mwmPrepHashedPatternGroups(ps);

    /* Select the Pattern Matcher Class */
    if ( ps->msNumPatterns < 5 )
    {
		printf("mwmPrepPatterns: msNumPatterns < 5, set ps->msMethod = MTH_BM\n");
        ps->msMethod =  MTH_BM;
    }
    else
    {
		printf("mwmPrepPatterns: msNumPatterns > 5, set ps->msMethod = MTH_HWM\n");
        ps->msMethod =  MTH_MWM;
    }

    /* Determine largest and smallest pattern sizes */
    for (i=0; i<ps->msNumPatterns; i++)
    {
        if (ps->msPatArray[i].psLen < small_value) small_value = ps->msPatArray[i].psLen;
        if (ps->msPatArray[i].psLen > large_value) large_value = ps->msPatArray[i].psLen;
    }

    m = (unsigned short) small_value;

    if( m > 255 ) m = 255;

    ps->msShiftLen = m;

    /* Setup Wu-Manber */
    if ( ps->msMethod == MTH_MWM )
    {
        if ( mwmCalB(ps) == 0 )
        {
            /* Build the Bad Char Shift Table per Wu & Manber */
            mwmPrepBadCharTable(ps);
        }
        else
        {
            /* Build the Bad Word Shift Table per Wu & Manber */
            mbmPrepBadWordTable( ps );
        }

        /* Min patterns is 1 byte */
        if ( ps->msShiftLen == 1 )
        {
            ps->search =  mwmSearchExNoBC;
			printf("mwmPrepPatterns: ps->msShiftLen==1, set ps->search=mwmSearchExNoBC\n");
        }
        /* Min patterns is >1 byte */
        else if ( (ps->msShiftLen >  1) && !ps->msLargeShifts )
        {
            if ( ps->msGBSrate < 50 )
            {
                ps->search =  mwmSearchExBC;
				printf("mwmPrepPatterns: ps->msShiftLen > 1 && ps->msGBSrate < 50, set ps->search=mwmSearchExBC\n");
            }
            else
            {
                ps->search = mwmSearchExBCNoGBS;
				printf("mwmPrepPatterns: ps->msShiftLen > 1 && ps->msGBSrate >= 50, set ps->search=mwmSearchExBCNoGBS\n");
            }
        }
        /* Min patterns is >1 byte - and we've been asked to use a 2 byte bad words shift instead. */
        else if ( (ps->msShiftLen >  1) && ps->msLargeShifts && ps->msShift2 )
        {
            ps->search =  mwmSearchExBW;
			printf("mwmPrepPatterns: ps->msShiftLen > 1 && msLargeShifts && msShift2, set ps->search=mwmSearchExBW\n");
        }
        /* Min patterns is >1 byte */
        else
        {
            ps->search =  mwmSearchExBCNoGBS;
			printf("mwmPrepPatterns: other cases, set ps->search=mwmSearchExBCNoGBS\n");
        }
#ifdef XXXX
        // if( ps->msDetails )   /* For testing - show this info */
        //    mwmGroupDetails( ps );
#endif

    }

    /* Initialize the Boyer-Moore Pattern data */
    if ( ps->msMethod == MTH_BM )
    {
        int i;

        /* Allocate and initialize the BMH data for each pattern */
        for (i=0;i<ps->msNumPatterns;i++)
        {
            ps->msPatArray[ i ].psBmh = hbm_prep( ps->msPatArray[ i ].psPat, ps->msPatArray[ i ].psLen );
        }
    }
    return 0;
}


/*
** Search a body of text or data for paterns
*/
int mwmSearch( void * pv,
               unsigned char * T, int n,
               int(*match)(int, int , int, void * ),
               void * data)
{
    unsigned char upper_text[65536];
    unsigned char* dst = T;

    MWM_STRUCT * ps = (MWM_STRUCT*)pv;

    if (ps->msNoCase)
    {
        if (n > 65536)
        {
            printf("TEXT's length should be no more than 65536\n");
            return 0;
        }

        ConvCaseToUpperEx(upper_text, T, n ); /* Copy and Convert to Upper Case */
        dst = upper_text;
    }

    if ( ps->msMethod == MTH_BM )
    {
        /* Boyer-Moore  */

        int i,nfound=0;
        unsigned char * Tx;

        for (i=0; i<ps->msNumPatterns; i++)
        {
            Tx = hbm_match( ps->msPatArray[i].psBmh, dst, n);

            if (Tx)
            {
                /* If we are case sensitive, do a final exact match test */
                if  (ps->msNoCase  && !ps->msPatArray[i].psNoCase)
                {
                    if (memcmp(ps->msPatArray[i].psPatCase,&T[Tx-dst], ps->msPatArray[i].psLen) )
                        continue; /* no match, next pattern please */
                }

                nfound++;
                int stop = match(ps->msPatArray[i].psID,  ps->msPatArray[i].psGID, (int)(Tx-dst), data);
                if (stop || ps->firststop)
                {
                    return nfound;
                }
            }
        }
        return nfound;
    }
    else /* MTH_MWM */
    {
        /* Wu-Manber */
        return ps->search(ps, dst, n, T, match, data );
    }
}







//##################################################################################
//   WMW wrapper
//##################################################################################
BEAP_MWM_SEARCH_HANDLE beap_mwm_search_init(SearchStru *searchconf, int nocase)
{
    int m;
    int n;
    MWM_STRUCT *  beap_mwm_search_handle  = mwmNew();

    if (!beap_mwm_search_handle)
    {
        return 0;
    }

    for (m=0; m<searchconf->search_group_num; m++)
    {
        for (n=0; n<searchconf->search_group[m].group_keyword_num; n++)
        {
            mwmAddPatternEx( beap_mwm_search_handle,
                             (unsigned char*)searchconf->search_group[m].group_keyword[n].keyword,
                             searchconf->search_group[m].group_keyword[n].keyword_length,
                             nocase,
                             0,
                             0,
                             n,
                             0,
                             m);
        }
    }
    mwmPrepPatterns(beap_mwm_search_handle);
    return beap_mwm_search_handle;
}


unsigned long beap_mwm_search_search(BEAP_MWM_SEARCH_HANDLE beap_mwm_search_handle,
                           unsigned char* search_result,
                           signed char *buf,
                           int length)
{
    SEARCH_SEARCH data;

    if (!beap_mwm_search_handle)
    {
        return 0;
    }

    data.search_result_keyword = search_result;
    data.search_result_group = 0;

	//printf("111111111111111\n");
    if (mwmSearch((void*)beap_mwm_search_handle, (unsigned char*)buf, length, match, (void*)&data))
    {
		//printf("222222222222222\n");
        return data.search_result_group;
    }
    else
    {
		//printf("333333333333333\n");
        return 0;
    }
}


int beap_mwm_search_free(BEAP_MWM_SEARCH_HANDLE beap_mwm_search_handle)
{
    mwmFree(beap_mwm_search_handle);
    beap_mwm_search_handle = NULL;
    return 1;
}


BEAP_MWM_SEARCH_HANDLE beap_mwm_search_init_single(SearchKeywordStruNoid * keyword_stru, int keyword_stru_num, int nocase)
{
    int m;
    MWM_STRUCT *  beap_mwm_search_handle  = mwmNew();

    if (!beap_mwm_search_handle)
    {
        return 0;
    }

    for (m=0; m<keyword_stru_num; m++)
    {
        mwmAddPatternEx(beap_mwm_search_handle,
                        (unsigned char*)keyword_stru[m].keyword,
                        keyword_stru[m].keyword_length,
                        nocase,
                        0,
                        0,
                        m,
                        0,
                        0);
    }
    mwmPrepPatterns(beap_mwm_search_handle);
    return beap_mwm_search_handle;
}


int beap_mwm_search_single(BEAP_MWM_SEARCH_HANDLE beap_mwm_search_handle,
                           SEARCH_RESULT_SINGLE search_result,
                           int search_result_num,
                           OFFSET_SINGLE offset,
                           int offset_num,
                           signed char* buf,
                           int length,
                           int firststop)
{
    int keyword_num;
    SINGLE_MATCH_RESULT  data;

    if (!beap_mwm_search_handle)
    {
        return 0;
    }

    keyword_num = beap_mwm_search_handle->msNumPatterns;

    if (search_result  != NULL &&  keyword_num > search_result_num)
    {
        return -1;
    }

    if (offset != NULL  && keyword_num > offset_num)
    {
        return -1;
    }


    beap_mwm_search_handle->firststop  = firststop;
    data.search_result = search_result;
    data.offset = offset;
    return mwmSearch((void*)beap_mwm_search_handle, (unsigned char*)buf, length, match_single, (void*)&data );
}


// for large keyword number and small group number
BEAP_MWM_SEARCH_HANDLE beap_mwm_search_init_group(SearchStru *searchconf, int nocase)
{
    int m;
    int n;
    MWM_STRUCT *  beap_mwm_search_handle  = mwmNew();

    if (!beap_mwm_search_handle)
    {
        return 0;
    }

    for (m=0; m<searchconf->search_group_num; m++)
    {
        for (n=0; n<searchconf->search_group[m].group_keyword_num; n++)
        {
            mwmAddPatternEx( beap_mwm_search_handle,
                             (unsigned char*)searchconf->search_group[m].group_keyword[n].keyword,
                             searchconf->search_group[m].group_keyword[n].keyword_length,
                             nocase,
                             0,
                             0,
                             n,
                             0,
                             m);
        }
    }
    mwmPrepPatterns(beap_mwm_search_handle);
    return beap_mwm_search_handle;
}


int beap_mwm_search_group(BEAP_MWM_SEARCH_HANDLE beap_mwm_search_handle,
                          SEARCH_RESULT_GROUP search_result_group,
                          SEARCH_RESULT_KEYWORD search_result_keyword,
                          OFFSET_GROUP offset,
                          signed char *buf,
                          int length,
                          int firststop)
{
    GROUP_MATCH_RESULT  data;

    if (!beap_mwm_search_handle)
    {
        return 0;
    }

    beap_mwm_search_handle->firststop = firststop;

    data.search_result_group = search_result_group;
    data.search_result_keyword = search_result_keyword;
    data.offset = offset;
    return mwmSearch((void*)beap_mwm_search_handle,
                     (unsigned char*)buf,
                     length,
                     match_group,
                     (void*)&data);
}


// for large group number and small keyword number
BEAP_MWM_SEARCH_HANDLE beap_mwm_search_init_group2(SearchStruNoid *searchconf, int nocase)
{
    int m;
    int n;
    MWM_STRUCT *  beap_mwm_search_handle  = mwmNew();

    if (!beap_mwm_search_handle)
    {
        return 0;
    }

    for (m=0; m<searchconf->search_group_num; m++)
    {
        for (n=0; n<searchconf->search_group[m].group_keyword_num; n++)
        {
            mwmAddPatternEx( beap_mwm_search_handle,
                             (unsigned char*)searchconf->search_group[m].group_keyword[n].keyword,
                             searchconf->search_group[m].group_keyword[n].keyword_length,
                             nocase,
                             0,
                             0,
                             n,
                             0,
                             m);
        }
    }
    mwmPrepPatterns(beap_mwm_search_handle);
    return beap_mwm_search_handle;
}


int beap_mwm_search_group2(BEAP_MWM_SEARCH_HANDLE beap_mwm_search_handle,
                           SEARCH_RESULT_GROUP2 search_result_group,
                           SEARCH_RESULT_KEYWORD2 search_result_keyword,
                           OFFSET_GROUP2 offset,
                           signed char *buf,
                           int length,
                           int firststop)
{
    GROUP_MATCH_RESULT2  data;

    if (!beap_mwm_search_handle)
    {
        return 0;
    }

    beap_mwm_search_handle->firststop = firststop;

    data.search_result_group = search_result_group;
    data.search_result_keyword = search_result_keyword;
    data.offset = offset;
    return mwmSearch((void*)beap_mwm_search_handle,
                     (unsigned char*)buf,
                     length,
                     match_group2,
                     (void*)&data);
}


BEAP_MWM_SEARCH_HANDLE beap_mwm_search_init_userdef(SearchStruUser * searchconf)
{
    int m,gid;
    int id=0;
    SearchKeywordStruUser * p;
    MWM_STRUCT * beap_mwm_search_handle = mwmNew();

    if (!beap_mwm_search_handle)
    {
        return 0;
    }

    for (m=0; m<searchconf->search_group_num; m++)
    {
        p = searchconf->search_group[m].group_keyword;
        gid = searchconf->search_group[m].group_id;
        while (p != NULL)
        {
            mwmAddPatternEx( beap_mwm_search_handle, (unsigned char *)p->keyword, p->keyword_length, p->nocase, 0, 0, id, 0, gid);
            p = p->next;
        }
        ++id;
    }
    beap_mwm_search_handle->msGroupNum = searchconf->search_group_num;
    mwmPrepPatterns(beap_mwm_search_handle);

    return beap_mwm_search_handle;
}


#define MIN(x,y) ((x)<(y)?(x):(y))
int beap_mwm_search_group_userdef(BEAP_MWM_SEARCH_HANDLE beap_mwm_search_handle,
                                  int * search_result_group,
                                  int search_result_group_num,
                                  signed char *buf,
                                  int length,
                                  int firststop)
{
    int m,flag=0;
    GROUP_RESULT_USERDEF data;
    int stat=0;
    int count = 0;

    if (!beap_mwm_search_handle)
    {
        return 0;
    }

    int group_num = beap_mwm_search_handle->msGroupNum;
    int result_temp[group_num];

    if (search_result_group == NULL)
    {
        search_result_group_num = 0;
    }

    if (search_result_group == NULL || firststop || search_result_group_num >= group_num)
    {
        data.search_result_group = search_result_group;
    }
    else
    {
        for (m=0; m<group_num; m++)
        {
            result_temp[m] = MWM_NOVALID_GROUP;
        }
        data.search_result_group = result_temp;
        flag = 1;
    }
    data.firststop = firststop;
    data.matched_group_num = 0;

    beap_mwm_search_handle->firststop = firststop;
    stat = mwmSearch((void*)beap_mwm_search_handle,
                     (unsigned char*)buf,
                     length,
                     match_group_userdef,
                     (void*)&data);

    if (stat > 0 && flag)
    {
        int  min_group_num = MIN(search_result_group_num, data.matched_group_num);
        for (m=0; m<group_num; m++)
        {
            if (result_temp[m] != MWM_NOVALID_GROUP)
            {
                search_result_group[count] = result_temp[m];
                count++;
                if (count > min_group_num - 1)
                {
                    break;
                }
            }
        }
    }
    return stat;
}

char iconv_utf8_gbk(char *to, int to_len, char *from, int from_len)
{
	iconv_t cd;
	int   _to_len, _from_len;

	cd = iconv_open("GBK","UTF-8");
	if (cd == (iconv_t)-1)
		return 0;
	_to_len = to_len;
	_from_len = from_len + 1;
	iconv(cd, (char **)&from, (size_t*)&_from_len, (char **)&to, (size_t*)&_to_len);
	iconv_close(cd);

	return 1;
}

char iconv_utf8_Big5(char *to, int to_len, char *from, int from_len)
{
	iconv_t cd;
	int   _to_len, _from_len;

	cd = iconv_open("Big5","UTF-8");
	if (cd == (iconv_t)-1)
		return 0;
	_to_len = to_len;
	_from_len = from_len + 1;
	iconv(cd, (char **)&from, (size_t*)&_from_len, (char **)&to, (size_t*)&_to_len);
	iconv_close(cd);

	return 1;
}
