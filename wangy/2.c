char cls_http_reassemble::beap_uncompress_new(unsigned char *uncompr, \
                       unsigned int *uncompr_len, \
                       unsigned char *compr, \
                       unsigned int *compr_len)
{
    int err = 0;
    z_stream d_stream;
    static char dummy_head[2] = {
        0x8 + 0x7*0x10,
        (((0x8 + 0x7*0x10)*0x100 + 30) / 31 * 31) & 0xFF,
    };

    d_stream.zalloc = NULL;
    d_stream.zfree = NULL;
    d_stream.opaque = NULL;
    d_stream.next_in = (Bytef*)compr;
    d_stream.avail_in = 0;
    d_stream.next_out = (Bytef*)uncompr;
   
    /* MAX_WBITS = 15 */
    if (inflateInit2(&d_stream, MAX_WBITS + 16) != Z_OK)
        return 1;

    while ( (d_stream.total_out < *uncompr_len) && (d_stream.total_in < *compr_len) )
    {
        d_stream.avail_in = d_stream.avail_out = 1;
        if ((err = inflate(&d_stream, Z_NO_FLUSH)) == Z_STREAM_END)
            break;

        if (err != Z_OK)
        {
            if (err == Z_DATA_ERROR)
            {
                d_stream.next_in = (Bytef*)dummy_head;
                d_stream.avail_in = sizeof(dummy_head);
                if ((err = inflate(&d_stream, Z_NO_FLUSH)) != Z_OK)
                {
                    return 1;
                }
            }
            else
                return 1;
        }
    }

    if (inflateEnd(&d_stream) != Z_OK)
        return 1;

    *uncompr_len = d_stream.total_out;

    return 0;

}

// end of the file

