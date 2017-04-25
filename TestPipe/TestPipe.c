/*
 * TestPipe.c
 *
 *  Created on: 2016年8月13日
 *      Author: zhangjl
 */

#include<unistd.h>
#include<sys/types.h>
#include<errno.h>

int main(int argc, char **argv)
{
	int		pipe_fd[2];
	pid_t 	pid;
	char		r_buf[4096];
	char		w_buf[4096*2];
	int		writenum, rnum;

	memset(r_buf, 0, sizeof(r_buf));
	memset(w_buf, 0, sizeof(w_buf));

	if (pipe(pipe_fd ) < 0)
	{
		printf("pipe create error!\n");
		return -1;
	}

	if ((pid = fork()) == 0)
	{
		printf("child process\n");
		close(pipe_fd[1]);

		while(1)
		{
			sleep(1);
			rnum = read(pipe_fd[0], r_buf, 1000);
			printf("child: readnum is %d\n", rnum);
		}

		close(pipe_fd[0]);
		exit(0);
	}
	else if (pid > 0)
	{
		printf("parent process\n");
		close(pipe_fd[0]);

		memset(w_buf, 0, sizeof(w_buf));
		if ((writenum = write(pipe_fd[1], w_buf, 1024)) == -1)
			printf("write to pipe error!\n");
		else
			printf("the bytes write to pipe is %d.\n", writenum);

		writenum = write(pipe_fd[1], w_buf, 4096);

		close(pipe_fd[1]);

		printf("parent process write over!");
	}

	return 0;
}
