/*
 * MainTestRedisConnection.c
 *
 *  Created on: Dec 27, 2016
 *      Author: root
 */

#include<stdio.h>
#include<stdlib.h>
#include<fcntl.h>
#include<stddef.h>
#include<stdarg.h>
#include<string.h>
#include<assert.h>
#include<hiredis/hiredis.h>

void doTest();

int main(int argc, char **argv)
{
	doTest();
	return 0;
}

void doTest()
{
	int timeout = 10000;
	struct timeval tv;
	tv.tv_sec = timeout /1000;
	tv.tv_usec = (timeout % 1000) * 1000;

	// 以带有超时德方式连接redis服务器，同时获取与redis连接的上下文对象。
	// 该对象将用于其后所有与Redis操作的函数。
	//redisContext* c = redisConnectWithTimeout("192.168.0.44", 6379, tv);
	redisContext* c = redisConnect("127.0.0.1", 6379);
	if (c->err)
	{
		redisFree(c);
		printf("redisConnectWithTimeout error!\n");
		return;
	}
	printf("redisConnect successful!\n");

	const char* command1 = "set stest1 value1";
	redisReply* r = (redisReply*)redisCommand(c, command1);
	// 需要注意的是，如果返回的对象是NULL，则表示客户端和服务器之间出现严重错误，必须重新连接。
	// 这里只是举例说明，简便起见，后面的命令就不再做这样的判断了。
	if (NULL == r)
	{
		redisFree(c);
		return;
	}

	// 不同的Redis命令返回的数据类型不同，在获取之前需要先判断它的实际类型。
	// 至于各种命令的返回值信息，可以参考Redis的官方文档。
	// 字符串类型的set命令的返回值的类型是REDIS_REPLY_STATUS，然后只有当返回值是"OK"时，
	// 才表示该命令执行成功。后面的例子以此类推，不再赘述。
	if (!(r->type == REDIS_REPLY_STATUS && strcasecmp(r->str, "OK") == 0))
	{
		printf("Failed to execute command[%s].\n\n", command1);
		freeReplyObject(r);
		redisFree(c);
		return;
	}

	// 由于后面重复使用该变量，所以需要提前释放，否则内存泄漏。
	freeReplyObject(r);
	printf("Succeed to execute command[%s].\n\n", command1);

	const char* command2 = "strlen stest1";
	r = (redisReply*)redisCommand(c, command2);
	if (r->type != REDIS_REPLY_INTEGER)
	{
		printf("Failed to execute command[%s].\n\n", command2);
		freeReplyObject(r);
		redisFree(c);
		return;
	}

	int length = r->integer;
	freeReplyObject(r);
	printf("The length of 'stest1' is %d.\n", length);
	printf("Succeed to execute command[%s].\n\n", command2);

	const char* command3 = "get stest1";
	r = (redisReply*)redisCommand(c, command3);
	if (r->type != REDIS_REPLY_STRING)
	{
		printf("Failed to execute command[%s].\n\n", command3);
		freeReplyObject(r);
		redisFree(c);
		return;
	}
	printf("The value of 'stest1' is %s.\n", r->str);
	freeReplyObject(r);
	printf("Succeed to execute command[%s].\n\n", command3);

	const char* command4 = "get stest2";
	r = (redisReply*)redisCommand(c, command4);
	// 这里需要先说明一下，由于stest2键并不存在，因此redis会返回空结果，这里只是为了演示。
	if (r->type != REDIS_REPLY_NIL)
	{
		printf("Failed to execute command[%s].\n\n", command4);
		freeReplyObject(r);
		redisFree(c);
		return;
	}
	freeReplyObject(r);
	printf("Succeed to execute command[%s].\n\n", command4);

	const char* command5 = "mget stest1 stest2";
	r = (redisReply*)redisCommand(c, command5);
	// 不论stest2存在与否，Redis都会给出结果，只是第二个值为nil.
	// 由于有多个值返回，因为返回应答德类型是数组类型
	if (r->type != REDIS_REPLY_ARRAY)
	{
		printf("Failed to execute command[%s].\n\n", command5);
		freeReplyObject(r);
		redisFree(c);
		// r->elements表示子元素的数量，不管请求的key是否存在，该值都等于请求的键德数量。
		assert(2 == r->elements);
		return;
	}

	int i = 0;
	for (i = 0; i < r->elements; ++i)
	{
		redisReply* childReply = r->element[i];
		// 之前已经介绍过，get命令返回的数据类型是string.
		// 对于不存在key的返回值，其类型为REDIS_REPLY_NIL。
		if (childReply->type == REDIS_REPLY_STRING)
		{
			printf("The value is %s.\n", childReply->str);
		}
	}

	// 对于每一个子应答，无需使用者单独释放，只需释放最外部的redisReply即可。
	freeReplyObject(r);
	printf("Succeed to execute command[%s].\n\n", command5);

	printf("Begin to test pipeline.\n");
	// 该命令只是将待发送的命令写入到上下文对象德输出缓冲区中，直到调用后面的
	// redisGetReply命令才会批量将缓冲区中的命令写出到Redis服务器。这样可以
	// 有效的减少客户端与服务器之间的同步等候时间，以及网络IO引起的延迟。
	// 至于管线的具体性能优势，可以研究相关redis管线相关的主题。
	if (REDIS_OK != redisAppendCommand(c, command1) ||
			REDIS_OK != redisAppendCommand(c, command2) ||
			REDIS_OK != redisAppendCommand(c, command3) ||
			REDIS_OK != redisAppendCommand(c, command4) ||
			REDIS_OK != redisAppendCommand(c, command5)
			)
	{
		redisFree(c);
		return;
	}

	redisReply* reply = NULL;
	// 对pipeline返回结果的处理方式，和前面代码的处理方式完全一致，这里就不重复给出了。
	if (REDIS_OK != redisGetReply(c, (void**)&reply))
	{
		printf("Failed to execute command[%s] with Pipeline.\n", command1);
		freeReplyObject(reply);
		redisFree(c);
	}
	freeReplyObject(reply);
	printf("Succeed to execute command[%s] with Pipeline.\n", command1);

	if (REDIS_OK != redisGetReply(c, (void**)&reply))
	{
		printf("Failed to execute command[%s] with Pipeline.\n", command2);
		freeReplyObject(reply);
		redisFree(c);
	}
	freeReplyObject(reply);
	printf("Succeed to execute command[%s] with Pipeline.\n", command2);

	if (REDIS_OK != redisGetReply(c, (void**)&reply))
	{
		printf("Failed to execute command[%s] with Pipeline.\n", command3);
		freeReplyObject(reply);
		redisFree(c);
	}
	freeReplyObject(reply);
	printf("Succeed to execute command[%s] with Pipeline.\n", command3);

	if (REDIS_OK != redisGetReply(c, (void**)&reply))
	{
		printf("Failed to execute command[%s] with Pipeline.\n", command4);
		freeReplyObject(reply);
		redisFree(c);
	}
	freeReplyObject(reply);
	printf("Succeed to execute command[%s] with Pipeline.\n", command4);

	if (REDIS_OK != redisGetReply(c, (void**)&reply))
	{
		printf("Failed to execute command[%s] with Pipeline.\n", command5);
		freeReplyObject(reply);
		redisFree(c);
	}
	freeReplyObject(reply);
	printf("Succeed to execute command[%s] with Pipeline.\n", command5);


	// 由于所有通过pipeline提交的命令结果均已为返回，如果此时继续调用redisGetReply，将
	// 会导致该函数阻塞并挂起当前线程，直到有新的通过管线提交的命令结果返回。
	// 最后，不要忘记在退出前释放当前连接的上下文对象。
	redisFree(c);
	return;
}




















