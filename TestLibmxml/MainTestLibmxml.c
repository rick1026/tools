
#include <mxml.h>

void WriteXMLFile(char *path);
void ReadBookXMLFile(char *path);

int main(int argc, char **argv)
{
	WriteXMLFile("./TestwriteXML.xml");
	ReadBookXMLFile("../templates/TestReadBook.xml");

	return 0;
}

void WriteXMLFile(char *filepath)
{
	mxml_node_t *xml;  /* <?xml ... ?> */
	mxml_node_t *data; /* <data> */
	mxml_node_t *node; /* <node> */
	mxml_node_t *group; /* <group> */

	xml = mxmlNewXML("1.0");
	data = mxmlNewElement(xml, "data");

	node = mxmlNewElement(data, "node");
	mxmlNewText(node, 0, "val1");
	node = mxmlNewElement(data, "node");
	mxmlNewText(node, 0, "val2");
	node = mxmlNewElement(data, "node");
	mxmlNewText(node, 0, "val3");

	group = mxmlNewElement(data, "group");
	node = mxmlNewElement(group, "node");
	mxmlNewText(node, 0, "val4");
	node = mxmlNewElement(group, "node");
	mxmlNewText(node, 0, "val5");
	node = mxmlNewElement(group, "node");
	mxmlNewText(node, 0, "val6");

	node = mxmlNewElement(data, "node");
	mxmlNewText(node, 0, "val7");
	node = mxmlNewElement(data, "node");
	mxmlNewText(node, 0, "val8");

	FILE *fd = fopen(filepath, "w");
	mxml_node_t *tree = xml;
	mxmlSaveFile(tree, fd, MXML_NO_CALLBACK);
	fclose(fd);

	return;
}

void ReadBookXMLFile(char *path)
{
	FILE *fd = fopen(path, "r");
	if (fd == NULL)
	{
		printf("ReadbookXMLFile: open file(%s) failed, return!\n", path);
		return;
	}

	// load xml file
	mxml_node_t *xml = mxmlLoadFile(NULL, fd, MXML_NO_CALLBACK);

	// define two nodes
	mxml_node_t *store = NULL;
	mxml_node_t *name = NULL;
	mxml_node_t *book = NULL;
	mxml_node_t *title = NULL;
	mxml_node_t *author = NULL;
	mxml_node_t *year = NULL;
	mxml_node_t *price = NULL;

	// search from the xml, name=book attr=category
	store = mxmlFindElement(xml, xml, "bookstore", NULL, NULL, MXML_DESCEND);
	while (store)
	{
		name = mxmlFindElement(store, xml, "name", NULL, NULL, MXML_DESCEND);
		if (name != NULL)
		{
			printf("\n\nbookstore's name is: %s\n", mxmlGetText(name, NULL));
		}
		else
		{
			printf("not found bookstore's name\n");
		}
		store = mxmlFindElement(store, xml, "bookstore", NULL, NULL, MXML_DESCEND);

	}

	return;

	book = mxmlFindElement(xml, xml, "book", "category", NULL, MXML_DESCEND);
	while(book)
	{
		title = mxmlFindElement(book, xml, "title", NULL, NULL, MXML_DESCEND);
		if (title == NULL)
		{
			printf("title not found\n");
			continue;
		}
		else
		{
			printf("\n\nbook's title is: %s\n", mxmlGetText(title, NULL));
			printf("book's category is: %s\n", mxmlElementGetAttr(book, "category"));
		}

		author = mxmlFindElement(book, xml, "author", NULL, NULL, MXML_DESCEND);
		if (author == NULL)
		{
			printf("author not found!\n");
			continue;
		}
		else
		{
			printf("book's author is: %s\n", mxmlGetText(author, NULL));
		}

		year = mxmlFindElement(book, xml, "year", NULL, NULL, MXML_DESCEND);
		if (year == NULL)
		{
			printf("year not found!\n");
			continue;
		}
		else
		{
			printf("book's year is: %s\n", mxmlGetText(year, NULL));
		}

		price = mxmlFindElement(book, xml, "price", NULL, NULL, MXML_DESCEND);
		if (price == NULL)
		{
			printf("price not found!\n");
			continue;
		}
		else
		{
			printf("book's price is: %s\n", mxmlGetText(price, NULL));
		}


		book = mxmlFindElement(title, xml, "book", "category", NULL, MXML_DESCEND);
	}

	mxmlDelete(xml);
	fclose(fd);
	return;

}

