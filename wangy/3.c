char cls_http_reassemble::beap_uncompress(unsigned char *uncompr, \
                       unsigned int  *uncompr_len, \
                       unsigned char *compr, \
                       unsigned int  *compr_len)
{
#define MAX_UNZIP_SIZE 320000
#define MIN_BUFSIZE    32768
#define MAX_BUFSIZE    1048576


    int err = Z_OK;
    int wbits = MAX_WBITS;
    int inits_num = 0;
	char *next = NULL;

    int     inlen;
    z_stream  stream;

    inlen = *compr_len;
	int bufsiz = inlen << 1;
	if ((bufsiz < MIN_BUFSIZE) || (bufsiz > MAX_BUFSIZE))
		bufsiz = MIN_BUFSIZE;
	bufsiz = *uncompr_len;
	next = (char*)compr;

    memset(&stream, 0, sizeof(z_stream));
    stream.next_in = (Bytef  *)compr;
    stream.avail_in = inlen;
    stream.next_out = (Bytef  *)uncompr;
    //stream.avail_out = MAX_UNZIP_SIZE;
    stream.avail_out = *uncompr_len;

    inits_num = 1;
    err = inflateInit2(&stream, wbits);
    if (err != Z_OK)
    {
        inflateEnd(&stream);
        return 1;
    }

    //while(inits_num <= 4)
    while(1)
    {
        stream.next_out = (Bytef  *)uncompr;
        stream.avail_out = *uncompr_len;

        err = inflate(&stream, Z_SYNC_FLUSH);

        if (err == Z_OK || err == Z_STREAM_END)
        {
            *uncompr_len = bufsiz - stream.avail_out;
            inflateEnd(&stream);
            return 0;
        }
        else if (err == Z_BUF_ERROR)
        {
            inflateEnd(&stream);
            return 1;
        }
        else if (err == Z_DATA_ERROR && \
                (*compr == 0x1f) && ((unsigned char)*(compr + 1) == 0x8b) &&\
                (inits_num == 1 /*|| inits_num == 3*/))
        {
    		char    *c = (char *)compr + 2;
	  		char     flags = 0;

            if (*c == Z_DEFLATED)
                c ++;
            else
			{
            	inflateEnd(&stream);
                return 1;
			}
            flags = *c;

            c += 7;
            if (flags & (1 << 2))
            {
                int size = (int)(*c | (*(c + 1) << 8));
                c += size;
            }

            if (flags & (1 << 3))
            {
                //while(*c != '\0')
                while(*c != '\0' && ((int)((unsigned char*)c - compr) < inlen))
                    c ++;
                c ++;
            }
            if (flags & (1 << 4))
            {
                //while(*c != '\0')
                while(*c != '\0' && (((unsigned char*)c - compr) < inlen))
                    c ++;
                c ++;
            }

            //inflateEnd(&stream);
            inflateReset(&stream);
			next = c;
            stream.next_in = (Bytef *)c;
			if ((unsigned char*)c - compr > inlen)
			{
				inflateEnd(&stream);
				return 1;
			}

            //inlen -= ((unsigned long) c - (unsigned long) compr);
            inlen -= (int)((unsigned char*)c - compr);
            //stream.avail_in = inlen;
            inflateInit2(&stream, wbits);
            inits_num ++;
            continue;
        }
        else if (err == Z_DATA_ERROR && inits_num <= 3)
        {
            wbits = -MAX_WBITS;
            //inflateEnd(&stream);
            inflateReset(&stream);
            //stream.next_in = (Bytef  *)compr;
            stream.next_in = (Bytef  *)next;
            stream.avail_in = *compr_len;
            inflateEnd(&stream);

			memset(uncompr, '\0', bufsiz);
            stream.next_out = (Bytef *)uncompr;
            stream.avail_out = bufsiz;
            err = inflateInit2(&stream, wbits);
            inits_num ++;
            if (err != Z_OK)
            {
                inflateEnd(&stream);
                return 1;
            }
            continue;
        }
		else
		{
            inflateEnd(&stream);
            return 1;
		}

    }
    inflateEnd(&stream);
    return 1;

}

// end of the file
