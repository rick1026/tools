#include<linux/init.h>
#include<linux/module.h>
#include<linux/moduleparam.h>
MODULE_LICENSE("Dual BSD/GPL");

static char *whom = "world";
static int  howmany = 5;
module_param(howmany, int, S_IRUGO);
module_param(whom, charp, S_IRUGO);

static int hello_init(void)
{
	int i = 0;
	for (i = 0; i < howmany; i++)
		printk(KERN_ALERT "Hello, %s world!\n", whom);
	return 0;
}

static void hello_exit(void)
{
	int i = 0;
		for (i = 0; i < howmany; i++)
	printk(KERN_ALERT "Goodbye, %s world!\n", whom);
}

module_init(hello_init);
module_exit(hello_exit);
