int ungzip(unsigned char* source,unsigned int len,unsigned char *des, unsigned int *des_len)
{
	#define segment_size 16384
	int ret,have;
	int offset=0;
	z_stream d_stream;
	Byte compr[segment_size]={0}, uncompr[segment_size*16]={0};
	memcpy(compr,(Byte*)source,len);
	uLong comprLen, uncomprLen;
	comprLen =len;//一开始写成了comprlen=sizeof(compr)以及comprlen=strlen(compr)，后来发现都不对。
//sizeof(compr)永远都是segment_size，显然不对，strlen(compr)也是不对的，因为strlen只算到\0之前，
//但是gzip或者zlib数据里\0很多。
uncomprLen = segment_size*16;
strcpy((char*)uncompr, "garbage");
d_stream.zalloc = Z_NULL;
d_stream.zfree = Z_NULL;
d_stream.opaque = Z_NULL;
d_stream.next_in = Z_NULL;//inflateInit和inflateInit2都必须初始化next_in和avail_in
d_stream.avail_in = 0;//deflateInit和deflateInit2则不用
ret = inflateInit2(&d_stream,47);
if(ret!=Z_OK)
{
   printf("inflateInit2 error:%d",ret);
   return ret;
}
d_stream.next_in=compr;
d_stream.avail_in=comprLen;
do
{
 d_stream.next_out=uncompr;
 d_stream.avail_out=uncomprLen;
 ret = inflate(&d_stream,Z_NO_FLUSH);
 assert(ret != Z_STREAM_ERROR);
 switch (ret)
 {
  case Z_NEED_DICT:
              ret = Z_DATA_ERROR;   
        case Z_DATA_ERROR:
        case Z_MEM_ERROR:
              (void)inflateEnd(&d_stream);
               return ret;
    }
 have=uncomprLen-d_stream.avail_out;
 memcpy(des+offset,uncompr,have);//这里一开始我写成了memcpy(des+offset,d_stream.next_out,have);
 //后来发现这是不对的，因为next_out指向的下次的输出，现在指向的是无有意义数据的内存。见下图
offset+=have;
}while(d_stream.avail_out==0);
inflateEnd(&d_stream);
memcpy(des+offset,"\0",1);
return ret;
}