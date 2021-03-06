char* ungzip(char*source,int len)
{
int err;
z_stream d_stream;
Byte compr[2000]={0}, uncompr[2000]={0};
memcpy(compr,(Byte*)source,len);
uLong comprLen, uncomprLen;
comprLen = sizeof(compr) / sizeof(compr[0]);
uncomprLen = comprLen;
strcpy((char*)uncompr, "garbage");

d_stream.zalloc =(alloc_func)0;
d_stream.zfree = (free_func)0;
d_stream.opaque = (voidpf)0;

d_stream.next_in =compr;
d_stream.avail_in = 0;
d_stream.next_out = uncompr;

err = inflateInit2(&d_stream,47);
if(err!=Z_OK)
{
   printf("inflateInit2 error:%d",err);
   return NULL;
}
while (d_stream.total_out < uncomprLen && d_stream.total_in <comprLen) {
d_stream.avail_in = d_stream.avail_out = 1; /* force small buffers */
err = inflate(&d_stream,Z_NO_FLUSH);
    if(err == Z_STREAM_END) break;
    if(err!=Z_OK)
    {
    printf("inflate error:%d",err);
    return NULL;
   }
}
err = inflateEnd(&d_stream);
if(err!=Z_OK)
{
   printf("inflateEnd error:%d",err);
   return NULL;
}
char* b = new char[d_stream.total_out+1];
bzero(b,d_stream.total_out+1);
memcpy(b,(char*)uncompr,d_stream.total_out);
return b;

}

 